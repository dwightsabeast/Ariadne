#!/usr/bin/env python3
"""
Ariadne - Web Scanner, Mapper & Archiver
A tool to scan, map, and archive websites with subdomain discovery.
"""

import os
import sys
import json
import csv
import time
import hashlib
import logging
import re
import socket
import ssl
import threading
import io
import datetime
from urllib.parse import urlparse, urljoin, urlunparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from bs4 import BeautifulSoup
import dns.resolver
import dns.exception

try:
    import whois as pywhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    logging.warning('python-whois not installed - WHOIS lookups disabled. Install via: pip install python-whois')

import base64

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
ARCHIVES_DIR = BASE_DIR / "archives"
EXPORTS_DIR = BASE_DIR / "exports"
LOGS_DIR = BASE_DIR / "logs"
SETTINGS_FILE = BASE_DIR / "settings.json"
SCHEDULES_FILE = BASE_DIR / "schedules.json"
SUBDOMAINS_FILE = BASE_DIR / "subdomains.txt"
PROXIES_FILE = BASE_DIR / "proxies.txt"

for d in [ARCHIVES_DIR, EXPORTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "ariadne.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ariadne")

# ─── Settings ────────────────────────────────────────────────────────────────

DEFAULT_SETTINGS = {
    "max_depth": 3,
    "max_threads": 10,
    "request_timeout": 15,
    "delay_between_requests": 0.2,
    "follow_external": False,
    "user_agent": "Ariadne/1.0 (Web Scanner & Archiver)",
    "respect_robots": True,
    "proxy_enabled": False,
    "proxy_rotate": False,
    "subdomain_threads": 20,
    "subdomain_timeout": 5,
    "archive_org_enabled": True,
}


def load_settings():
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                saved = json.load(f)
            merged = {**DEFAULT_SETTINGS, **saved}
            return merged
        except Exception:
            logger.warning("Failed to load settings, using defaults")
    return dict(DEFAULT_SETTINGS)


def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


settings = load_settings()

# ─── Proxy Management ────────────────────────────────────────────────────────

def load_proxies():
    proxies = []
    if PROXIES_FILE.exists():
        with open(PROXIES_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(line)
    return proxies


proxy_list = load_proxies()
proxy_index = 0
proxy_lock = threading.Lock()


def get_proxy():
    global proxy_index
    if not settings.get("proxy_enabled") or not proxy_list:
        return None
    with proxy_lock:
        proxy = proxy_list[proxy_index % len(proxy_list)]
        if settings.get("proxy_rotate"):
            proxy_index += 1
        return {"http": proxy, "https": proxy}


# ─── HTTP Session ────────────────────────────────────────────────────────────

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": settings.get("user_agent", DEFAULT_SETTINGS["user_agent"])})
    return session


# ─── Active Scan State ───────────────────────────────────────────────────────

scan_state = {
    "active": False,
    "progress": 0,
    "total": 0,
    "status": "idle",
    "current_url": "",
    "results": [],
    "errors": [],
    "cancel_requested": False,
}
scan_lock = threading.Lock()

subdomain_state = {
    "active": False,
    "progress": 0,
    "total": 0,
    "status": "idle",
    "results": [],
    "errors": [],
    "cancel_requested": False,
}
subdomain_lock = threading.Lock()

# ─── Flask App ───────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=None)
CORS(app)


@app.route("/")
def serve_index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(load_settings())


@app.route("/api/settings", methods=["POST"])
def update_settings():
    global settings
    data = request.json
    settings.update(data)
    save_settings(settings)
    return jsonify({"ok": True, "settings": settings})


# ─── Website Scanning ────────────────────────────────────────────────────────

def normalize_url(url):
    """Normalize a URL for deduplication."""
    parsed = urlparse(url)
    # Remove fragment, normalize scheme
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/") or "/",
        parsed.params,
        parsed.query,
        "",  # remove fragment
    ))
    return normalized


def extract_links(html, base_url):
    """Extract all links from HTML content."""
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
            href = tag.get("href") or tag.get("src")
            if href:
                absolute = urljoin(base_url, href)
                normalized = normalize_url(absolute)
                if normalized.startswith(("http://", "https://")):
                    links.add(normalized)
    except Exception as e:
        logger.debug(f"Error parsing links from {base_url}: {e}")
    return links


def check_security_headers(headers):
    """Analyze security headers in HTTP response."""
    security_headers = {
        "Strict-Transport-Security": {"present": False, "value": None},
        "Content-Security-Policy": {"present": False, "value": None},
        "X-Content-Type-Options": {"present": False, "value": None},
        "X-Frame-Options": {"present": False, "value": None},
        "X-XSS-Protection": {"present": False, "value": None},
        "Referrer-Policy": {"present": False, "value": None},
        "Permissions-Policy": {"present": False, "value": None},
        "Cross-Origin-Opener-Policy": {"present": False, "value": None},
        "Cross-Origin-Resource-Policy": {"present": False, "value": None},
    }
    for header_name in security_headers:
        val = headers.get(header_name)
        if val:
            security_headers[header_name] = {"present": True, "value": val}
    return security_headers


def crawl_url(session, url, timeout):
    """Fetch a single URL and return its data."""
    result = {
        "url": url,
        "status_code": None,
        "content_type": None,
        "title": None,
        "links": [],
        "security_headers": {},
        "response_time": None,
        "error": None,
        "size": 0,
    }
    try:
        start = time.time()
        resp = session.get(
            url, timeout=timeout, allow_redirects=True, proxies=get_proxy()
        )
        result["response_time"] = round((time.time() - start) * 1000)
        result["status_code"] = resp.status_code
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["size"] = len(resp.content)
        result["security_headers"] = check_security_headers(resp.headers)

        if "text/html" in result["content_type"]:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                result["title"] = title_tag.get_text(strip=True) if title_tag else None
            except Exception:
                pass
            result["links"] = list(extract_links(resp.text, url))

    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def run_scan(start_url, max_depth, follow_external):
    """Execute a full website scan."""
    global scan_state

    with scan_lock:
        scan_state["active"] = True
        scan_state["progress"] = 0
        scan_state["total"] = 1
        scan_state["status"] = "scanning"
        scan_state["results"] = []
        scan_state["errors"] = []
        scan_state["cancel_requested"] = False

    session = create_session()
    parsed_start = urlparse(start_url)
    base_domain = parsed_start.netloc.lower()
    timeout = settings.get("request_timeout", 15)
    delay = settings.get("delay_between_requests", 0.2)

    visited = set()
    queue = [(normalize_url(start_url), 0)]
    all_results = []

    while queue:
        if scan_state["cancel_requested"]:
            with scan_lock:
                scan_state["status"] = "cancelled"
                scan_state["active"] = False
            return

        url, depth = queue.pop(0)

        if url in visited:
            continue
        if depth > max_depth:
            continue

        visited.add(url)

        with scan_lock:
            scan_state["current_url"] = url
            scan_state["progress"] = len(visited)

        result = crawl_url(session, url, timeout)
        all_results.append(result)

        with scan_lock:
            scan_state["results"] = all_results.copy()

        if result["error"]:
            with scan_lock:
                scan_state["errors"].append({"url": url, "error": result["error"]})

        # Queue discovered links
        if depth < max_depth and result["links"]:
            for link in result["links"]:
                if link in visited:
                    continue
                link_domain = urlparse(link).netloc.lower()
                is_internal = (link_domain == base_domain or
                               link_domain.endswith("." + base_domain))

                if is_internal or follow_external:
                    queue.append((link, depth + 1))
                    with scan_lock:
                        scan_state["total"] = len(visited) + len(queue)

        if delay > 0:
            time.sleep(delay)

    with scan_lock:
        scan_state["active"] = False
        scan_state["status"] = "complete"
        scan_state["results"] = all_results

    logger.info(f"Scan complete: {len(all_results)} pages crawled from {start_url}")


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    if scan_state["active"]:
        return jsonify({"error": "A scan is already running"}), 409

    data = request.json
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    max_depth = data.get("max_depth", settings.get("max_depth", 3))
    follow_external = data.get("follow_external", settings.get("follow_external", False))

    thread = threading.Thread(
        target=run_scan, args=(url, max_depth, follow_external), daemon=True
    )
    thread.start()

    return jsonify({"ok": True, "message": "Scan started"})


@app.route("/api/scan/status", methods=["GET"])
def scan_status():
    with scan_lock:
        return jsonify({
            "active": scan_state["active"],
            "progress": scan_state["progress"],
            "total": scan_state["total"],
            "status": scan_state["status"],
            "current_url": scan_state["current_url"],
            "result_count": len(scan_state["results"]),
            "error_count": len(scan_state["errors"]),
        })


@app.route("/api/scan/results", methods=["GET"])
def scan_results():
    with scan_lock:
        return jsonify({
            "results": scan_state["results"],
            "errors": scan_state["errors"],
            "status": scan_state["status"],
        })


@app.route("/api/scan/cancel", methods=["POST"])
def cancel_scan():
    with scan_lock:
        scan_state["cancel_requested"] = True
    return jsonify({"ok": True})


# ─── Subdomain Discovery ────────────────────────────────────────────────────

def load_subdomain_wordlist():
    """Load subdomain wordlist for brute force."""
    words = []
    if SUBDOMAINS_FILE.exists():
        with open(SUBDOMAINS_FILE) as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
    return words


def detect_wildcard(domain):
    """Check if domain has wildcard DNS."""
    random_sub = f"ariadne-wildcard-test-{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}"
    try:
        answers = dns.resolver.resolve(random_sub, "A")
        wildcard_ips = {rdata.to_text() for rdata in answers}
        return wildcard_ips
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return set()
    except Exception:
        return set()


def _source_crtsh(domain, ua):
    """Certificate Transparency via crt.sh."""
    subdomains = set()
    resp = requests.get(
        f"https://crt.sh/?q=%.{domain}&output=json",
        timeout=20,
        headers={"User-Agent": ua},
    )
    if resp.status_code == 200:
        data = resp.json()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(f".{domain}") and sub != domain:
                    subdomains.add(sub)
    return subdomains


def _source_hackertarget(domain, ua):
    """HackerTarget free host search API."""
    subdomains = set()
    resp = requests.get(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        timeout=15,
        headers={"User-Agent": ua},
    )
    if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
        for line in resp.text.strip().splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith(f".{domain}") and sub != domain:
                    subdomains.add(sub)
    return subdomains


def _source_alienvault(domain, ua):
    """AlienVault OTX passive DNS - no API key needed."""
    subdomains = set()
    resp = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=15,
        headers={"User-Agent": ua},
    )
    if resp.status_code == 200:
        data = resp.json()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").lower()
            if hostname.endswith(f".{domain}") and hostname != domain:
                subdomains.add(hostname)
    return subdomains


def _source_urlscan(domain, ua):
    """urlscan.io search API - no API key needed for basic queries."""
    subdomains = set()
    resp = requests.get(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
        timeout=15,
        headers={"User-Agent": ua},
    )
    if resp.status_code == 200:
        data = resp.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            host = page.get("domain", "").lower()
            if host.endswith(f".{domain}") and host != domain:
                subdomains.add(host)
    return subdomains


def _source_anubis(domain, ua):
    """Anubis-DB subdomain API."""
    subdomains = set()
    resp = requests.get(
        f"https://jldc.me/anubis/subdomains/{domain}",
        timeout=15,
        headers={"User-Agent": ua},
    )
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            for sub in data:
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") and sub != domain:
                    subdomains.add(sub)
    return subdomains


# Registry of passive sources - tried in order
PASSIVE_SOURCES = [
    ("crt.sh", _source_crtsh),
    ("HackerTarget", _source_hackertarget),
    ("AlienVault OTX", _source_alienvault),
    ("urlscan.io", _source_urlscan),
    ("Anubis-DB", _source_anubis),
]


def passive_subdomain_discovery(domain):
    """Discover subdomains via multiple passive sources with fallbacks.

    Tries every source independently; failures in one don't block others.
    Returns (subdomains_set, source_report_dict).
    """
    all_subdomains = set()
    source_report = {}
    ua = settings.get("user_agent", "Ariadne/1.0")

    for name, fn in PASSIVE_SOURCES:
        try:
            found = fn(domain, ua)
            new_count = len(found - all_subdomains)
            all_subdomains.update(found)
            source_report[name] = {"count": len(found), "new": new_count, "ok": True, "error": None}
            logger.info(f"Passive source {name}: {len(found)} subs ({new_count} new)")
        except Exception as e:
            source_report[name] = {"count": 0, "new": 0, "ok": False, "error": str(e)}
            logger.warning(f"Passive source {name} failed for {domain}: {e}")

    # DNS records that might reveal subdomains (MX, NS, TXT, SOA)
    dns_found = set()
    for record_type in ["MX", "NS", "TXT", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                text = rdata.to_text().lower()
                parts = re.findall(r"[\w.-]+\." + re.escape(domain), text)
                for part in parts:
                    sub = part.rstrip(".")
                    if sub.endswith(f".{domain}") and sub != domain:
                        dns_found.add(sub)
        except Exception:
            pass
    new_dns = len(dns_found - all_subdomains)
    all_subdomains.update(dns_found)
    source_report["DNS Records"] = {"count": len(dns_found), "new": new_dns, "ok": True, "error": None}

    return all_subdomains, source_report


def resolve_subdomain(subdomain, timeout, wildcard_ips):
    """Try to resolve a subdomain via DNS."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(subdomain, "A")
        ips = {rdata.to_text() for rdata in answers}

        # Filter wildcard matches
        if wildcard_ips and ips == wildcard_ips:
            return None

        return {
            "subdomain": subdomain,
            "ips": list(ips),
            "source": "bruteforce",
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    except Exception:
        return None


def verify_subdomain(subdomain, timeout):
    """Verify a passively discovered subdomain via DNS."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(subdomain, "A")
        ips = [rdata.to_text() for rdata in answers]
        return {"subdomain": subdomain, "ips": ips, "source": "passive"}
    except Exception:
        return {"subdomain": subdomain, "ips": [], "source": "passive"}


def run_subdomain_scan(domain):
    """Execute full subdomain discovery."""
    global subdomain_state

    with subdomain_lock:
        subdomain_state["active"] = True
        subdomain_state["progress"] = 0
        subdomain_state["status"] = "discovering"
        subdomain_state["results"] = []
        subdomain_state["errors"] = []
        subdomain_state["cancel_requested"] = False
        subdomain_state["source_report"] = {}

    timeout = settings.get("subdomain_timeout", 5)
    max_threads = settings.get("subdomain_threads", 20)
    all_results = []

    # Phase 1: Wildcard detection
    with subdomain_lock:
        subdomain_state["status"] = "checking wildcards"
    logger.info(f"Checking wildcard DNS for {domain}")
    wildcard_ips = detect_wildcard(domain)
    if wildcard_ips:
        logger.info(f"Wildcard DNS detected for {domain}: {wildcard_ips}")

    # Phase 2: Passive discovery
    with subdomain_lock:
        subdomain_state["status"] = "passive discovery"
    logger.info(f"Running passive subdomain discovery for {domain}")
    passive_subs, source_report = passive_subdomain_discovery(domain)
    logger.info(f"Found {len(passive_subs)} subdomains passively")

    with subdomain_lock:
        subdomain_state["source_report"] = source_report

    # Verify passive results
    for sub in passive_subs:
        if subdomain_state["cancel_requested"]:
            break
        result = verify_subdomain(sub, timeout)
        if result:
            all_results.append(result)
            with subdomain_lock:
                subdomain_state["results"] = all_results.copy()
                subdomain_state["progress"] += 1

    # Phase 3: Active brute force
    with subdomain_lock:
        subdomain_state["status"] = "active bruteforce"
    wordlist = load_subdomain_wordlist()
    already_found = {r["subdomain"] for r in all_results}

    with subdomain_lock:
        subdomain_state["total"] = len(passive_subs) + len(wordlist)

    logger.info(f"Starting brute force with {len(wordlist)} words")

    def check_word(word):
        sub = f"{word}.{domain}"
        if sub in already_found:
            return None
        return resolve_subdomain(sub, timeout, wildcard_ips)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_word, word): word for word in wordlist}
        for future in as_completed(futures):
            if subdomain_state["cancel_requested"]:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            try:
                result = future.result()
                if result:
                    all_results.append(result)
                    with subdomain_lock:
                        subdomain_state["results"] = all_results.copy()
            except Exception:
                pass
            with subdomain_lock:
                subdomain_state["progress"] += 1

    with subdomain_lock:
        subdomain_state["active"] = False
        subdomain_state["status"] = "complete"
        subdomain_state["results"] = all_results
        subdomain_state["wildcard"] = bool(wildcard_ips)

    logger.info(f"Subdomain scan complete: {len(all_results)} found for {domain}")


@app.route("/api/subdomains/start", methods=["POST"])
def start_subdomain_scan():
    if subdomain_state["active"]:
        return jsonify({"error": "A subdomain scan is already running"}), 409

    data = request.json
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    # Clean domain
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    thread = threading.Thread(
        target=run_subdomain_scan, args=(domain,), daemon=True
    )
    thread.start()

    return jsonify({"ok": True, "message": "Subdomain scan started"})


@app.route("/api/subdomains/status", methods=["GET"])
def subdomain_status():
    with subdomain_lock:
        return jsonify({
            "active": subdomain_state["active"],
            "progress": subdomain_state["progress"],
            "total": subdomain_state["total"],
            "status": subdomain_state["status"],
            "result_count": len(subdomain_state["results"]),
            "source_report": subdomain_state.get("source_report", {}),
        })


@app.route("/api/subdomains/results", methods=["GET"])
def subdomain_results():
    with subdomain_lock:
        return jsonify({
            "results": subdomain_state["results"],
            "status": subdomain_state["status"],
            "wildcard": subdomain_state.get("wildcard", False),
            "source_report": subdomain_state.get("source_report", {}),
        })


@app.route("/api/subdomains/cancel", methods=["POST"])
def cancel_subdomain_scan():
    with subdomain_lock:
        subdomain_state["cancel_requested"] = True
    return jsonify({"ok": True})


# ─── Archive.org Integration ────────────────────────────────────────────────

@app.route("/api/archive/save", methods=["POST"])
def archive_save():
    """Save URL(s) to Archive.org via the Wayback Machine Save API."""
    data = request.json
    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    results = []
    session = create_session()

    for url in urls:
        try:
            resp = session.get(
                f"https://web.archive.org/save/{url}",
                timeout=30,
                allow_redirects=True,
            )
            if resp.status_code in (200, 302):
                archive_url = resp.headers.get("Content-Location") or resp.headers.get("Location", "")
                if archive_url and not archive_url.startswith("http"):
                    archive_url = f"https://web.archive.org{archive_url}"
                results.append({
                    "url": url,
                    "success": True,
                    "archive_url": archive_url or f"https://web.archive.org/web/{url}",
                })
            else:
                results.append({
                    "url": url,
                    "success": False,
                    "error": f"HTTP {resp.status_code}",
                })
        except Exception as e:
            results.append({"url": url, "success": False, "error": str(e)[:200]})

    return jsonify({"results": results})


@app.route("/api/archive/check", methods=["POST"])
def archive_check():
    """Check if a URL exists in Archive.org and get latest snapshot."""
    data = request.json
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    try:
        resp = requests.get(
            f"https://archive.org/wayback/available?url={url}",
            timeout=15,
        )
        data = resp.json()
        snapshot = data.get("archived_snapshots", {}).get("closest")
        return jsonify({
            "url": url,
            "archived": snapshot is not None,
            "snapshot": snapshot,
        })
    except Exception as e:
        return jsonify({"url": url, "error": str(e)[:200]}), 500


@app.route("/api/archive/diff", methods=["POST"])
def archive_diff():
    """Compare current page with its latest Archive.org snapshot."""
    data = request.json
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    session = create_session()

    try:
        # Get current page
        current_resp = session.get(url, timeout=15, proxies=get_proxy())
        current_html = current_resp.text

        # Get latest archived version
        avail_resp = requests.get(
            f"https://archive.org/wayback/available?url={url}",
            timeout=15,
        )
        avail_data = avail_resp.json()
        snapshot = avail_data.get("archived_snapshots", {}).get("closest")

        if not snapshot:
            return jsonify({
                "url": url,
                "has_diff": None,
                "message": "No archived version found",
            })

        # Fetch archived version
        archive_url = snapshot.get("url", "")
        archived_resp = session.get(archive_url, timeout=20)
        archived_html = archived_resp.text

        # Strip Wayback Machine toolbar/injection from archived HTML
        archived_clean = re.sub(
            r'<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*?<!-- END WAYBACK TOOLBAR INSERT -->',
            '', archived_html, flags=re.DOTALL
        )

        # Simple text comparison
        current_text = BeautifulSoup(current_html, "html.parser").get_text(separator="\n", strip=True)
        archived_text = BeautifulSoup(archived_clean, "html.parser").get_text(separator="\n", strip=True)

        current_hash = hashlib.sha256(current_text.encode()).hexdigest()
        archived_hash = hashlib.sha256(archived_text.encode()).hexdigest()

        has_changes = current_hash != archived_hash

        # Generate simple diff summary
        current_lines = set(current_text.splitlines())
        archived_lines = set(archived_text.splitlines())
        added = current_lines - archived_lines
        removed = archived_lines - current_lines

        return jsonify({
            "url": url,
            "has_diff": has_changes,
            "snapshot_date": snapshot.get("timestamp", ""),
            "snapshot_url": archive_url,
            "current_hash": current_hash,
            "archived_hash": archived_hash,
            "lines_added": len(added),
            "lines_removed": len(removed),
            "sample_added": list(added)[:10],
            "sample_removed": list(removed)[:10],
        })

    except Exception as e:
        return jsonify({"url": url, "error": str(e)[:200]}), 500


# ─── Local Archiving ────────────────────────────────────────────────────────

@app.route("/api/archive/local", methods=["POST"])
def archive_local():
    """Save page(s) locally as HTML files."""
    data = request.json
    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    session = create_session()
    results = []
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    for url in urls:
        try:
            resp = session.get(url, timeout=15, proxies=get_proxy())
            parsed = urlparse(url)
            safe_name = re.sub(r'[^\w\-.]', '_', parsed.netloc + parsed.path)[:100]
            filename = f"{safe_name}_{timestamp}.html"
            filepath = ARCHIVES_DIR / filename

            with open(filepath, "w", encoding="utf-8") as f:
                # Add archival metadata header
                f.write(f"<!-- Archived by Ariadne on {datetime.datetime.now().isoformat()} -->\n")
                f.write(f"<!-- Original URL: {url} -->\n")
                f.write(f"<!-- HTTP Status: {resp.status_code} -->\n\n")
                f.write(resp.text)

            results.append({
                "url": url,
                "success": True,
                "filename": filename,
                "size": len(resp.text),
            })
        except Exception as e:
            results.append({"url": url, "success": False, "error": str(e)[:200]})

    return jsonify({"results": results})


@app.route("/api/archive/local/list", methods=["GET"])
def list_local_archives():
    """List locally archived files."""
    files = []
    for f in sorted(ARCHIVES_DIR.iterdir(), reverse=True):
        if f.is_file() and f.suffix == ".html":
            stat = f.stat()
            files.append({
                "filename": f.name,
                "size": stat.st_size,
                "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
    return jsonify({"files": files})


@app.route("/api/archive/local/<filename>", methods=["GET"])
def get_local_archive(filename):
    """Download a locally archived file."""
    safe = Path(filename).name  # prevent path traversal
    filepath = ARCHIVES_DIR / safe
    if filepath.exists():
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


# ─── Export ──────────────────────────────────────────────────────────────────

@app.route("/api/export/csv", methods=["POST"])
def export_csv():
    """Export scan results to CSV."""
    data = request.json
    export_type = data.get("type", "scan")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ariadne_{export_type}_{timestamp}.csv"
    filepath = EXPORTS_DIR / filename

    if export_type == "scan":
        results = scan_state.get("results", [])
        if not results:
            return jsonify({"error": "No scan results to export"}), 400

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Status", "Title", "Content-Type", "Size (bytes)", "Response Time (ms)", "Error"])
            for r in results:
                writer.writerow([
                    r.get("url", ""),
                    r.get("status_code", ""),
                    r.get("title", ""),
                    r.get("content_type", ""),
                    r.get("size", 0),
                    r.get("response_time", ""),
                    r.get("error", ""),
                ])

    elif export_type == "subdomains":
        results = subdomain_state.get("results", [])
        if not results:
            return jsonify({"error": "No subdomain results to export"}), 400

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain", "IP Addresses", "Source"])
            for r in results:
                writer.writerow([
                    r.get("subdomain", ""),
                    ", ".join(r.get("ips", [])),
                    r.get("source", ""),
                ])

    elif export_type == "sitemap":
        results = scan_state.get("results", [])
        if not results:
            return jsonify({"error": "No scan results for sitemap"}), 400

        # Generate XML sitemap
        filename = f"sitemap_{timestamp}.xml"
        filepath = EXPORTS_DIR / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
            for r in results:
                if r.get("status_code") == 200 and "text/html" in (r.get("content_type") or ""):
                    f.write(f"  <url>\n    <loc>{r['url']}</loc>\n")
                    f.write(f"    <lastmod>{datetime.date.today().isoformat()}</lastmod>\n")
                    f.write(f"  </url>\n")
            f.write("</urlset>\n")

        return jsonify({
            "ok": True,
            "filename": filename,
            "download": f"/api/export/download/{filename}",
        })

    else:
        return jsonify({"error": f"Unknown export type: {export_type}"}), 400

    return jsonify({
        "ok": True,
        "filename": filename,
        "download": f"/api/export/download/{filename}",
    })


@app.route("/api/export/download/<filename>", methods=["GET"])
def download_export(filename):
    safe = Path(filename).name
    filepath = EXPORTS_DIR / safe
    if filepath.exists():
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


# ─── Schedules ───────────────────────────────────────────────────────────────

def load_schedules():
    if SCHEDULES_FILE.exists():
        try:
            with open(SCHEDULES_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_schedules(schedules):
    with open(SCHEDULES_FILE, "w") as f:
        json.dump(schedules, f, indent=2)


@app.route("/api/schedules", methods=["GET"])
def get_schedules():
    return jsonify({"schedules": load_schedules()})


@app.route("/api/schedules", methods=["POST"])
def create_schedule():
    data = request.json
    schedules = load_schedules()
    schedule = {
        "id": hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
        "url": data.get("url", ""),
        "interval_hours": data.get("interval_hours", 24),
        "max_depth": data.get("max_depth", 2),
        "archive_to_org": data.get("archive_to_org", True),
        "archive_local": data.get("archive_local", True),
        "diff_before_archive": data.get("diff_before_archive", True),
        "enabled": True,
        "created": datetime.datetime.now().isoformat(),
        "last_run": None,
    }
    schedules.append(schedule)
    save_schedules(schedules)
    return jsonify({"ok": True, "schedule": schedule})


@app.route("/api/schedules/<schedule_id>", methods=["DELETE"])
def delete_schedule(schedule_id):
    schedules = load_schedules()
    schedules = [s for s in schedules if s.get("id") != schedule_id]
    save_schedules(schedules)
    return jsonify({"ok": True})


@app.route("/api/schedules/<schedule_id>/toggle", methods=["POST"])
def toggle_schedule(schedule_id):
    schedules = load_schedules()
    for s in schedules:
        if s.get("id") == schedule_id:
            s["enabled"] = not s.get("enabled", True)
            break
    save_schedules(schedules)
    return jsonify({"ok": True, "schedules": schedules})


# ─── Quick Tools ─────────────────────────────────────────────────────────────

@app.route("/api/tools/check-url", methods=["POST"])
def check_url():
    """Quick check a single URL (status, headers, title)."""
    data = request.json
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = create_session()
    result = crawl_url(session, url, settings.get("request_timeout", 15))
    return jsonify(result)


@app.route("/api/tools/broken-links", methods=["POST"])
def check_broken_links():
    """Check URLs for broken (4xx/5xx) responses."""
    data = request.json
    urls = data.get("urls", [])
    if not urls:
        # Use scan results if no URLs provided
        urls = [r["url"] for r in scan_state.get("results", []) if r.get("url")]

    if not urls:
        return jsonify({"error": "No URLs to check"}), 400

    session = create_session()
    results = []
    timeout = settings.get("request_timeout", 15)

    for url in urls[:500]:  # Cap at 500
        try:
            resp = session.head(url, timeout=timeout, allow_redirects=True, proxies=get_proxy())
            status = resp.status_code
        except Exception as e:
            status = 0

        is_broken = status == 0 or status >= 400
        results.append({
            "url": url,
            "status_code": status,
            "broken": is_broken,
        })

    broken_count = sum(1 for r in results if r["broken"])
    return jsonify({
        "results": results,
        "total": len(results),
        "broken_count": broken_count,
    })


# ─── Intelligence Extraction Helpers ─────────────────────────────────────────

# Patterns for analytics/tracking ID extraction
ANALYTICS_PATTERNS = {
    "Google Analytics (UA)": [
        re.compile(r'(?:UA-\d{4,10}(?:-\d{1,4})?)'),
    ],
    "Google Analytics (GA4)": [
        re.compile(r'(?:G-[A-Z0-9]{6,12})'),
    ],
    "Google Tag Manager": [
        re.compile(r'(?:GTM-[A-Z0-9]{4,8})'),
    ],
    "Google AdSense": [
        re.compile(r'(?:ca-pub-\d{10,16})'),
    ],
    "Facebook Pixel": [
        re.compile(r'(?:fbq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d{12,16})[\'"])'),
    ],
    "Hotjar": [
        re.compile(r'(?:hjid[\'"]?\s*[:=]\s*(\d{5,9}))'),
        re.compile(r'(?:hotjar\.com.*?(\d{6,9}))'),
    ],
    "Yandex Metrica": [
        re.compile(r'(?:ym\s*\(\s*(\d{6,10}))'),
        re.compile(r'(?:metrika\.yandex.*?id[\'"]?\s*[:=]\s*(\d{6,10}))'),
    ],
    "Matomo/Piwik": [
        re.compile(r'(?:setSiteId[\'",\s]+(\d+))'),
        re.compile(r'(?:idsite[\'"]?\s*[:=]\s*(\d+))'),
    ],
    "Cloudflare Web Analytics": [
        re.compile(r'(?:beacon\.min\.js.*?token[\'"]?\s*[:=]\s*[\'"]([a-f0-9]{32})[\'"])'),
    ],
    "Microsoft Clarity": [
        re.compile(r'(?:clarity\.ms.*?[\'"]([a-z0-9]{8,12})[\'"])'),
    ],
    "Intercom": [
        re.compile(r'(?:intercomSettings.*?app_id[\'"]?\s*[:=]\s*[\'"]([a-z0-9]+)[\'"])'),
    ],
    "Hubspot": [
        re.compile(r'(?:hs-script-loader.*?(\d{6,10}))'),
        re.compile(r'(?:js\.hs-analytics\.net/analytics.*?(\d{6,10}))'),
    ],
    "Segment": [
        re.compile(r'(?:analytics\.load\s*\(\s*[\'"]([a-zA-Z0-9]+)[\'"])'),
    ],
    "Mixpanel": [
        re.compile(r'(?:mixpanel\.init\s*\(\s*[\'"]([a-f0-9]{32})[\'"])'),
    ],
    "Heap": [
        re.compile(r'(?:heap\.load\s*\(\s*[\'"](\d{8,12})[\'"])'),
    ],
    "Pinterest Tag": [
        re.compile(r'(?:pintrk\s*\(\s*[\'"]load[\'"]\s*,\s*[\'"](\d{13})[\'"])'),
    ],
    "TikTok Pixel": [
        re.compile(r'(?:ttq\.load\s*\(\s*[\'"]([A-Z0-9]{18,22})[\'"])'),
    ],
    "Snap Pixel": [
        re.compile(r'(?:snaptr\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"]([a-f0-9-]{36})[\'"])'),
    ],
    "LinkedIn Insight": [
        re.compile(r'(?:_linkedin_partner_id\s*=\s*[\'"]?(\d{5,10}))'),
    ],
    "Twitter Pixel": [
        re.compile(r'(?:twq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"]([a-z0-9]+)[\'"])'),
    ],
}

# Technology detection patterns
TECH_PATTERNS = {
    "WordPress": {
        "html": [r'wp-content/', r'wp-includes/', r'/xmlrpc\.php'],
        "headers": {"X-Powered-By": r"WordPress"},
        "meta_generator": r"WordPress\s*([\d.]+)?",
    },
    "Drupal": {
        "html": [r'Drupal\.settings', r'drupal\.js', r'/sites/default/'],
        "headers": {"X-Drupal-Cache": r".*", "X-Generator": r"Drupal"},
        "meta_generator": r"Drupal\s*([\d.]+)?",
    },
    "Joomla": {
        "html": [r'/media/jui/', r'/components/com_'],
        "meta_generator": r"Joomla",
    },
    "Shopify": {
        "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "headers": {"X-ShopId": r"\d+"},
    },
    "Wix": {
        "html": [r'wix\.com', r'wixstatic\.com', r'X-Wix-'],
    },
    "Squarespace": {
        "html": [r'squarespace\.com', r'static\.squarespace'],
    },
    "React": {
        "html": [r'__NEXT_DATA__', r'_next/', r'react(?:\.production|\.development)', r'__react'],
    },
    "Vue.js": {
        "html": [r'vue\.(?:min\.)?js', r'__vue__', r'v-cloak'],
    },
    "Angular": {
        "html": [r'ng-version', r'angular(?:\.min)?\.js'],
    },
    "jQuery": {
        "html": [r'jquery[\.-](\d+\.\d+(?:\.\d+)?)'],
    },
    "Bootstrap": {
        "html": [r'bootstrap[\.-](\d+\.\d+(?:\.\d+)?)', r'bootstrapcdn\.com'],
    },
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".*"},
    },
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d+\.\d+))?"},
    },
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d+\.\d+))?"},
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS(?:/(\d+\.\d+))?"},
    },
    "PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/(\d+\.\d+))?"},
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"},
    },
    "Express": {
        "headers": {"X-Powered-By": r"Express"},
    },
    "Varnish": {
        "headers": {"Via": r"varnish", "X-Varnish": r".*"},
    },
    "Amazon S3": {
        "headers": {"Server": r"AmazonS3"},
    },
    "Google Tag Manager": {
        "html": [r'googletagmanager\.com/gtm\.js'],
    },
    "reCAPTCHA": {
        "html": [r'google\.com/recaptcha', r'g-recaptcha'],
    },
    "Stripe": {
        "html": [r'js\.stripe\.com'],
    },
    "PayPal": {
        "html": [r'paypal\.com/sdk', r'paypalobjects\.com'],
    },
    "Google Maps": {
        "html": [r'maps\.googleapis\.com', r'maps\.google\.com'],
    },
    "Sentry": {
        "html": [r'sentry\.io', r'browser\.sentry-cdn\.com'],
    },
}

# Social media URL patterns
SOCIAL_PATTERNS = {
    "Twitter/X": re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]{1,15})(?:\?|/|$)', re.I),
    "Facebook": re.compile(r'https?://(?:www\.)?facebook\.com/([a-zA-Z0-9_.]+)(?:\?|/|$)', re.I),
    "Instagram": re.compile(r'https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_.]+)(?:\?|/|$)', re.I),
    "LinkedIn": re.compile(r'https?://(?:www\.)?linkedin\.com/(?:company|in)/([a-zA-Z0-9_-]+)', re.I),
    "YouTube": re.compile(r'https?://(?:www\.)?youtube\.com/(?:@|channel/|c/|user/)([a-zA-Z0-9_-]+)', re.I),
    "GitHub": re.compile(r'https?://(?:www\.)?github\.com/([a-zA-Z0-9_-]+)(?:\?|/|$)', re.I),
    "TikTok": re.compile(r'https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9_.]+)', re.I),
    "Pinterest": re.compile(r'https?://(?:www\.)?pinterest\.com/([a-zA-Z0-9_-]+)', re.I),
    "Reddit": re.compile(r'https?://(?:www\.)?reddit\.com/(?:r|u|user)/([a-zA-Z0-9_-]+)', re.I),
    "Medium": re.compile(r'https?://(?:www\.)?medium\.com/@([a-zA-Z0-9_.]+)', re.I),
    "Telegram": re.compile(r'https?://(?:t\.me|telegram\.me)/([a-zA-Z0-9_]+)', re.I),
    "Discord": re.compile(r'https?://(?:www\.)?discord\.(?:gg|com/invite)/([a-zA-Z0-9_-]+)', re.I),
}


def extract_analytics_ids(html_source):
    """Extract all analytics and tracking IDs from page source."""
    found = {}
    for name, patterns in ANALYTICS_PATTERNS.items():
        ids = set()
        for pattern in patterns:
            for match in pattern.finditer(html_source):
                # Some patterns have groups, some match the whole thing
                val = match.group(1) if match.lastindex else match.group(0)
                if val:
                    ids.add(val)
        if ids:
            found[name] = sorted(ids)
    return found


def extract_tech_fingerprint(html_source, headers_dict, url=""):
    """Detect technologies from HTML and HTTP headers."""
    detected = {}
    headers_lower = {k.lower(): v for k, v in headers_dict.items()}

    for tech_name, patterns in TECH_PATTERNS.items():
        version = None
        matched = False

        # Check HTML patterns
        for html_pat in patterns.get("html", []):
            m = re.search(html_pat, html_source, re.I)
            if m:
                matched = True
                if m.lastindex:
                    version = m.group(1)
                break

        # Check header patterns
        for header_name, header_pat in patterns.get("headers", {}).items():
            header_val = headers_lower.get(header_name.lower(), "")
            if header_val:
                m = re.search(header_pat, header_val, re.I)
                if m:
                    matched = True
                    if m.lastindex:
                        version = m.group(1)
                    break

        # Check meta generator
        if not matched and "meta_generator" in patterns:
            gen_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                html_source, re.I
            )
            if gen_match:
                m = re.search(patterns["meta_generator"], gen_match.group(1), re.I)
                if m:
                    matched = True
                    if m.lastindex:
                        version = m.group(1)

        if matched:
            detected[tech_name] = version

    return detected


def extract_social_contacts(html_source):
    """Extract social media profiles and contact info from HTML."""
    result = {"social": {}, "emails": [], "phones": []}

    # Social media
    for platform, pattern in SOCIAL_PATTERNS.items():
        handles = set()
        for m in pattern.finditer(html_source):
            handle = m.group(1)
            # Filter out common non-profile paths
            if handle.lower() not in ("share", "sharer", "intent", "dialog", "plugins",
                                       "hashtag", "search", "watch", "embed", "login",
                                       "signup", "help", "about", "legal", "privacy",
                                       "terms", "policy", "settings", "explore"):
                handles.add(handle)
        if handles:
            result["social"][platform] = sorted(handles)

    # Email addresses
    email_pat = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
    emails = set()
    for m in email_pat.finditer(html_source):
        email = m.group(1).lower()
        # Filter out common false positives
        if not any(x in email for x in [".png", ".jpg", ".gif", ".svg", ".css", ".js",
                                         "example.com", "sentry.io", "webpack"]):
            emails.add(email)
    result["emails"] = sorted(emails)

    # Phone numbers (common formats)
    phone_pat = re.compile(r'(?:tel:|phone|call).*?([\+]?1?\s*[-.\(]?\s*\d{3}\s*[-.\)]?\s*\d{3}\s*[-.]?\s*\d{4})')
    phones = set()
    for m in phone_pat.finditer(html_source, re.I):
        phone = re.sub(r'\s+', '', m.group(1))
        if len(phone) >= 10:
            phones.add(phone)
    result["phones"] = sorted(phones)

    return result


def compute_favicon_hash(session, url):
    """Fetch favicon and return its MD5 hash (used by Shodan for correlation)."""
    parsed = urlparse(url)
    favicon_urls = [
        f"{parsed.scheme}://{parsed.netloc}/favicon.ico",
    ]
    for fav_url in favicon_urls:
        try:
            resp = session.get(fav_url, timeout=10, proxies=get_proxy())
            if resp.status_code == 200 and len(resp.content) > 0:
                import base64
                b64 = base64.b64encode(resp.content)
                # MurmurHash3 is what Shodan uses, but MD5 works for our correlation
                return {
                    "url": fav_url,
                    "md5": hashlib.md5(resp.content).hexdigest(),
                    "sha256": hashlib.sha256(resp.content).hexdigest(),
                    "size": len(resp.content),
                }
        except Exception:
            pass
    return None


def compute_content_hashes(html_source):
    """Compute hashes of page content for similarity detection."""
    # Strip tags for text-only comparison
    text_only = re.sub(r'<[^>]+>', ' ', html_source)
    text_only = re.sub(r'\s+', ' ', text_only).strip()

    # Hash of full HTML structure
    # Remove variable content (timestamps, nonces, etc.)
    structure = re.sub(r'(?:nonce|timestamp|csrf|token)[=:]["\']?[^"\'>\s]+', '', html_source)
    structure = re.sub(r'\d{10,}', 'TIMESTAMP', structure)  # Unix timestamps

    return {
        "text_md5": hashlib.md5(text_only.encode()).hexdigest(),
        "text_length": len(text_only),
        "html_length": len(html_source),
    }


# ─── WHOIS Intelligence ─────────────────────────────────────────────────────

def whois_lookup(domain):
    """Perform WHOIS lookup and extract key attribution fields."""
    if not HAS_WHOIS:
        return {"domain": domain, "error": "python-whois not installed"}
    global pywhois
    try:
        w = pywhois.whois(domain)
        # Normalize the data
        result = {
            "domain": domain,
            "registrar": w.registrar if hasattr(w, "registrar") else None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "registrant": {
                "name": getattr(w, "name", None),
                "org": getattr(w, "org", None),
                "email": None,
                "country": getattr(w, "country", None),
                "state": getattr(w, "state", None),
                "city": getattr(w, "city", None),
                "address": getattr(w, "address", None),
            },
            "status": w.status if hasattr(w, "status") else None,
            "dnssec": getattr(w, "dnssec", None),
            "raw": None,
        }

        # Handle dates (can be lists)
        for date_field in ["creation_date", "expiration_date", "updated_date"]:
            val = getattr(w, date_field, None)
            if isinstance(val, list):
                val = val[0] if val else None
            if val:
                result[date_field] = val.isoformat() if hasattr(val, "isoformat") else str(val)

        # Handle emails
        emails = getattr(w, "emails", None)
        if emails:
            if isinstance(emails, list):
                result["registrant"]["email"] = emails[0]
                result["all_emails"] = emails
            else:
                result["registrant"]["email"] = emails
                result["all_emails"] = [emails]

        # Name servers
        ns = getattr(w, "name_servers", None)
        if ns:
            if isinstance(ns, list):
                result["name_servers"] = [n.lower() for n in ns]
            else:
                result["name_servers"] = [ns.lower()]

        # Store raw text for manual inspection
        if hasattr(w, "text"):
            result["raw"] = w.text[:3000] if isinstance(w.text, str) else str(w.text)[:3000]

        return result
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ─── DNS Deep Analysis ──────────────────────────────────────────────────────

def dns_full_enumeration(domain):
    """Enumerate all DNS record types and extract infrastructure details."""
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 8
    resolver.lifetime = 8

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.exception.DNSException:
            pass
        except Exception:
            pass

    # Extract infrastructure details from records
    infrastructure = {
        "ips": records.get("A", []) + records.get("AAAA", []),
        "mail_servers": [],
        "name_servers": records.get("NS", []),
        "spf_includes": [],
        "dmarc": None,
        "dkim_selectors": [],
        "caa_issuers": [],
        "cdn_detected": None,
    }

    # Parse MX records
    for mx in records.get("MX", []):
        parts = mx.split()
        if len(parts) >= 2:
            infrastructure["mail_servers"].append({
                "priority": int(parts[0]),
                "server": parts[1].rstrip(".")
            })

    # Parse TXT records for SPF, DMARC, DKIM hints
    for txt in records.get("TXT", []):
        txt_clean = txt.strip('"')
        if txt_clean.startswith("v=spf1"):
            includes = re.findall(r'include:(\S+)', txt_clean)
            infrastructure["spf_includes"] = includes
        if "v=DMARC1" in txt_clean:
            infrastructure["dmarc"] = txt_clean

    # Try DMARC record
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                infrastructure["dmarc"] = txt
                records.setdefault("DMARC", []).append(txt)
    except Exception:
        pass

    # Parse CAA records
    for caa in records.get("CAA", []):
        parts = caa.split()
        if len(parts) >= 3:
            infrastructure["caa_issuers"].append(parts[2].strip('"'))

    # Detect CDN from A record IPs or CNAME
    cname_val = " ".join(records.get("CNAME", []))
    cdn_indicators = {
        "Cloudflare": ["cloudflare", "cf-"],
        "AWS CloudFront": ["cloudfront.net"],
        "Akamai": ["akamai", "edgekey", "edgesuite"],
        "Fastly": ["fastly"],
        "Google Cloud": ["googleusercontent", "googleplex"],
        "Azure CDN": ["azureedge.net", "azure"],
        "Sucuri": ["sucuri"],
        "Incapsula/Imperva": ["incapdns", "imperva"],
    }
    for cdn_name, patterns in cdn_indicators.items():
        for pat in patterns:
            if pat in cname_val.lower() or pat in " ".join(records.get("A", [])).lower():
                infrastructure["cdn_detected"] = cdn_name
                break
        if infrastructure["cdn_detected"]:
            break

    return {"domain": domain, "records": records, "infrastructure": infrastructure}


def dns_reverse_lookup(ip):
    """Perform reverse DNS lookup on an IP address."""
    try:
        import socket
        hostnames = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": hostnames[0], "aliases": list(hostnames[1])}
    except Exception as e:
        return {"ip": ip, "hostname": None, "error": str(e)}


# ─── TLS Certificate Analysis ──────────────────────────────────────────────

def tls_cert_analysis(domain, port=443):
    """Connect to domain via TLS and extract certificate details."""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, port))
        cert_der = conn.getpeercert(binary_form=True)
        cert_dict = conn.getpeercert()
        conn.close()

        # Parse subject
        subject = {}
        for field in cert_dict.get("subject", ()):
            for key, value in field:
                subject[key] = value

        # Parse issuer
        issuer = {}
        for field in cert_dict.get("issuer", ()):
            for key, value in field:
                issuer[key] = value

        # SANs
        sans = []
        for san_type, san_value in cert_dict.get("subjectAltName", ()):
            sans.append({"type": san_type, "value": san_value})

        # Certificate fingerprints
        cert_sha256 = hashlib.sha256(cert_der).hexdigest()
        cert_md5 = hashlib.md5(cert_der).hexdigest()

        # Public key fingerprint (for cross-cert correlation)
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization, hashes
            cert_obj = x509.load_der_x509_certificate(cert_der)
            pub_key_bytes = cert_obj.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pubkey_sha256 = hashlib.sha256(pub_key_bytes).hexdigest()
            serial_number = str(cert_obj.serial_number)
            sig_algorithm = cert_obj.signature_algorithm_oid._name if hasattr(cert_obj.signature_algorithm_oid, '_name') else str(cert_obj.signature_algorithm_oid.dotted_string)
        except Exception:
            pubkey_sha256 = None
            serial_number = cert_dict.get("serialNumber", None)
            sig_algorithm = None

        return {
            "domain": domain,
            "subject": subject,
            "issuer": issuer,
            "sans": sans,
            "san_domains": [s["value"] for s in sans if s["type"] == "DNS"],
            "not_before": cert_dict.get("notBefore"),
            "not_after": cert_dict.get("notAfter"),
            "serial_number": serial_number,
            "version": cert_dict.get("version"),
            "cert_sha256": cert_sha256,
            "cert_md5": cert_md5,
            "pubkey_sha256": pubkey_sha256,
            "signature_algorithm": sig_algorithm,
            "organization": subject.get("organizationName"),
            "common_name": subject.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "issuer_cn": issuer.get("commonName"),
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ─── IP & Hosting Correlation ───────────────────────────────────────────────

def reverse_ip_lookup(ip, ua="Ariadne/1.0"):
    """Find other domains hosted on the same IP via HackerTarget."""
    result = {"ip": ip, "domains": [], "error": None}
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=15,
            headers={"User-Agent": ua},
        )
        if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
            domains = [line.strip() for line in resp.text.strip().splitlines() if line.strip()]
            result["domains"] = domains
            result["count"] = len(domains)
    except Exception as e:
        result["error"] = str(e)
    return result


def ip_info_lookup(ip, ua="Ariadne/1.0"):
    """Get ASN, organization, and geolocation for an IP."""
    result = {"ip": ip, "asn": None, "org": None, "geo": None, "error": None}

    # Use ip-api.com (free, no key)
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,asname",
            timeout=10,
            headers={"User-Agent": ua},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result["asn"] = data.get("as", "").split()[0] if data.get("as") else None
                result["asn_name"] = data.get("asname")
                result["org"] = data.get("org")
                result["isp"] = data.get("isp")
                result["geo"] = {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Correlation Engine ─────────────────────────────────────────────────────

intel_db = {
    "domains": {},   # domain -> {whois, dns, tls, analytics, tech, social, ...}
    "correlations": [],  # [{type, key, value, domains, strength, description}]
}
intel_lock = threading.Lock()

# Investigation state
intel_state = {
    "active": False,
    "domain": None,
    "progress": 0,
    "total": 7,
    "status": "idle",
    "steps_completed": [],
    "cancel_requested": False,
}


def store_domain_intel(domain, category, data):
    """Store intelligence data for a domain."""
    with intel_lock:
        if domain not in intel_db["domains"]:
            intel_db["domains"][domain] = {
                "first_seen": datetime.datetime.utcnow().isoformat(),
                "categories": {},
            }
        intel_db["domains"][domain]["categories"][category] = {
            "data": data,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }


def find_correlations():
    """Cross-reference all stored intel to find links between domains."""
    with intel_lock:
        domains_data = intel_db["domains"]

    if len(domains_data) < 2:
        return []

    correlations = []
    domain_list = list(domains_data.keys())

    # Helper to add correlation
    def add_corr(corr_type, key, value, domain_set, strength, desc):
        if len(domain_set) >= 2:
            correlations.append({
                "type": corr_type,
                "key": key,
                "value": str(value),
                "domains": sorted(domain_set),
                "strength": strength,
                "description": desc,
            })

    # ── Analytics ID matches (STRONGEST) ──
    analytics_map = {}  # (platform, id) -> set of domains
    for domain, info in domains_data.items():
        analytics = info["categories"].get("analytics", {}).get("data", {})
        for platform, ids in analytics.items():
            for aid in (ids if isinstance(ids, list) else [ids]):
                key = (platform, aid)
                analytics_map.setdefault(key, set()).add(domain)
    for (platform, aid), doms in analytics_map.items():
        add_corr("analytics", platform, aid, doms, 0.95,
                 f"Shared {platform} ID: {aid}")

    # ── TLS Certificate matches ──
    # Same SAN domains on one cert
    san_map = {}  # cert_sha256 -> (domains_in_san, set of investigated domains)
    pubkey_map = {}  # pubkey_sha256 -> set of domains
    for domain, info in domains_data.items():
        tls = info["categories"].get("tls", {}).get("data", {})
        if tls.get("cert_sha256"):
            san_map.setdefault(tls["cert_sha256"], {"san_domains": set(), "investigated": set()})
            san_map[tls["cert_sha256"]]["investigated"].add(domain)
            for sd in tls.get("san_domains", []):
                san_map[tls["cert_sha256"]]["san_domains"].add(sd)
        if tls.get("pubkey_sha256"):
            pubkey_map.setdefault(tls["pubkey_sha256"], set()).add(domain)

    for cert_hash, cert_info in san_map.items():
        # Check if any SAN domains match other investigated domains
        san_doms = cert_info["san_domains"]
        inv_doms = cert_info["investigated"]
        matching = set()
        for sd in san_doms:
            base = sd.lstrip("*.")
            for d in domain_list:
                if d == base or d.endswith("." + base):
                    matching.add(d)
        matching.update(inv_doms)
        add_corr("tls_san", "Shared Certificate", cert_hash[:16] + "...", matching, 0.90,
                 f"Domains share TLS certificate covering {len(san_doms)} SANs")

    for pk_hash, doms in pubkey_map.items():
        add_corr("tls_pubkey", "Shared Public Key", pk_hash[:16] + "...", doms, 0.85,
                 "Domains use certificates with the same public key")

    # ── WHOIS matches ──
    whois_email_map = {}
    whois_org_map = {}
    whois_ns_map = {}
    for domain, info in domains_data.items():
        whois_data = info["categories"].get("whois", {}).get("data", {})
        if whois_data.get("error"):
            continue
        # Registrant email
        for email in whois_data.get("all_emails", []):
            if email and "privacy" not in email.lower() and "proxy" not in email.lower():
                whois_email_map.setdefault(email.lower(), set()).add(domain)
        # Organization
        org = whois_data.get("registrant", {}).get("org")
        if org and org.lower() not in ("", "none", "redacted for privacy", "data protected"):
            whois_org_map.setdefault(org.lower(), set()).add(domain)
        # Name servers
        for ns in whois_data.get("name_servers", []):
            ns_base = ".".join(ns.rstrip(".").split(".")[-2:])
            whois_ns_map.setdefault(ns_base, set()).add(domain)

    for email, doms in whois_email_map.items():
        add_corr("whois_email", "Registrant Email", email, doms, 0.92,
                 f"Shared WHOIS email: {email}")
    for org, doms in whois_org_map.items():
        add_corr("whois_org", "Registrant Org", org, doms, 0.80,
                 f"Shared WHOIS organization: {org}")
    for ns, doms in whois_ns_map.items():
        if len(doms) >= 2:
            # Common NS providers are weak signals
            common_ns = ["cloudflare.com", "awsdns", "google.com", "domaincontrol.com",
                        "registrar-servers.com", "dns.com", "hichina.com"]
            strength = 0.40 if any(c in ns for c in common_ns) else 0.70
            add_corr("whois_ns", "Shared Nameservers", ns, doms, strength,
                     f"Shared nameserver provider: {ns}")

    # ── DNS / Infrastructure matches ──
    ip_map = {}
    mx_map = {}
    spf_map = {}
    for domain, info in domains_data.items():
        dns_data = info["categories"].get("dns", {}).get("data", {})
        if not dns_data or dns_data.get("error"):
            continue
        infra = dns_data.get("infrastructure", {})
        for ip in infra.get("ips", []):
            ip_map.setdefault(ip, set()).add(domain)
        for mx in infra.get("mail_servers", []):
            mx_base = ".".join(mx.get("server", "").rstrip(".").split(".")[-2:])
            mx_map.setdefault(mx_base, set()).add(domain)
        for spf_inc in infra.get("spf_includes", []):
            spf_map.setdefault(spf_inc, set()).add(domain)

    for ip, doms in ip_map.items():
        add_corr("shared_ip", "Shared IP", ip, doms, 0.75,
                 f"Hosted on same IP: {ip}")
    for mx, doms in mx_map.items():
        common_mx = ["google.com", "outlook.com", "protection.outlook.com",
                     "mail.protection.outlook.com", "googlemail.com"]
        strength = 0.30 if any(c in mx for c in common_mx) else 0.65
        add_corr("shared_mx", "Shared MX", mx, doms, strength,
                 f"Same mail provider: {mx}")
    for spf, doms in spf_map.items():
        common_spf = ["_spf.google.com", "spf.protection.outlook.com", "amazonses.com"]
        strength = 0.25 if spf in common_spf else 0.60
        add_corr("shared_spf", "Shared SPF", spf, doms, strength,
                 f"Same SPF include: {spf}")

    # ── Social media matches ──
    social_map = {}
    for domain, info in domains_data.items():
        social = info["categories"].get("social", {}).get("data", {})
        for platform, handles in social.get("social", {}).items():
            for handle in handles:
                social_map.setdefault((platform, handle.lower()), set()).add(domain)
    for (platform, handle), doms in social_map.items():
        add_corr("social", f"{platform}", handle, doms, 0.88,
                 f"Shared {platform} profile: @{handle}")

    # ── Email contact matches ──
    contact_email_map = {}
    for domain, info in domains_data.items():
        social = info["categories"].get("social", {}).get("data", {})
        for email in social.get("emails", []):
            contact_email_map.setdefault(email, set()).add(domain)
    for email, doms in contact_email_map.items():
        add_corr("contact_email", "Contact Email", email, doms, 0.85,
                 f"Shared contact email: {email}")

    # ── Technology fingerprint matches (weak but cumulative) ──
    tech_map = {}
    for domain, info in domains_data.items():
        tech = info["categories"].get("tech", {}).get("data", {})
        for tech_name, version in tech.items():
            key = f"{tech_name} {version}" if version else tech_name
            tech_map.setdefault(key, set()).add(domain)
    # Only flag unusual shared tech (skip very common ones)
    common_tech = {"jQuery", "Bootstrap", "Cloudflare", "Google Tag Manager",
                   "reCAPTCHA", "Nginx", "Apache", "PHP"}
    for tech_key, doms in tech_map.items():
        tech_base = tech_key.split()[0]
        if len(doms) >= 2 and tech_base not in common_tech:
            add_corr("technology", "Shared Tech", tech_key, doms, 0.35,
                     f"Same technology: {tech_key}")

    # ── Favicon hash matches ──
    favicon_map = {}
    for domain, info in domains_data.items():
        fav = info["categories"].get("favicon", {}).get("data", {})
        if fav and fav.get("md5"):
            favicon_map.setdefault(fav["md5"], set()).add(domain)
    for fav_hash, doms in favicon_map.items():
        add_corr("favicon", "Shared Favicon", fav_hash[:16] + "...", doms, 0.80,
                 "Identical favicon image")

    # Sort by strength descending
    correlations.sort(key=lambda x: (-x["strength"], x["type"]))

    with intel_lock:
        intel_db["correlations"] = correlations

    return correlations


def build_graph_data():
    """Build nodes and edges for relationship graph visualization."""
    with intel_lock:
        domains_data = intel_db["domains"]
        correlations = intel_db["correlations"]

    nodes = []
    edges = []
    node_ids = {}

    # Domain nodes
    for i, domain in enumerate(domains_data.keys()):
        node_id = f"domain_{i}"
        node_ids[domain] = node_id
        cats = domains_data[domain].get("categories", {})
        nodes.append({
            "id": node_id,
            "label": domain,
            "type": "domain",
            "categories": list(cats.keys()),
        })

    # Correlation edges
    for corr in correlations:
        doms = corr["domains"]
        for i in range(len(doms)):
            for j in range(i + 1, len(doms)):
                if doms[i] in node_ids and doms[j] in node_ids:
                    edges.append({
                        "source": node_ids[doms[i]],
                        "target": node_ids[doms[j]],
                        "type": corr["type"],
                        "label": corr["key"],
                        "value": corr["value"],
                        "strength": corr["strength"],
                        "description": corr["description"],
                    })

    return {"nodes": nodes, "edges": edges}


def run_investigation(domain):
    """Run full OSINT investigation on a domain."""
    global intel_state

    with intel_lock:
        intel_state["active"] = True
        intel_state["domain"] = domain
        intel_state["progress"] = 0
        intel_state["total"] = 9
        intel_state["status"] = "starting"
        intel_state["steps_completed"] = []
        intel_state["cancel_requested"] = False

    ua = settings.get("user_agent", "Ariadne/1.0")
    session = create_session()

    def step(name, fn, category):
        if intel_state["cancel_requested"]:
            return
        with intel_lock:
            intel_state["status"] = name
        try:
            data = fn()
            store_domain_intel(domain, category, data)
            logger.info(f"Intel [{domain}] {name}: OK")
        except Exception as e:
            store_domain_intel(domain, category, {"error": str(e)})
            logger.warning(f"Intel [{domain}] {name}: {e}")
        with intel_lock:
            intel_state["progress"] += 1
            intel_state["steps_completed"].append(name)

    # Step 1: Fetch homepage - extract analytics, tech, social
    def do_homepage():
        result = {}
        try:
            url = f"https://{domain}"
            resp = session.get(url, timeout=15, allow_redirects=True, proxies=get_proxy())
            html = resp.text
            headers = dict(resp.headers)

            analytics = extract_analytics_ids(html)
            store_domain_intel(domain, "analytics", analytics)

            tech = extract_tech_fingerprint(html, headers, url)
            store_domain_intel(domain, "tech", tech)

            social = extract_social_contacts(html)
            store_domain_intel(domain, "social", social)

            content = compute_content_hashes(html)
            store_domain_intel(domain, "content", content)

            fav = compute_favicon_hash(session, url)
            if fav:
                store_domain_intel(domain, "favicon", fav)

            result = {"url": url, "status": resp.status_code, "title": None}
            if "text/html" in resp.headers.get("Content-Type", ""):
                soup = BeautifulSoup(html, "html.parser")
                title_tag = soup.find("title")
                result["title"] = title_tag.get_text(strip=True) if title_tag else None
        except Exception as e:
            result = {"error": str(e)}
        return result

    step("Fetching homepage & extracting intel", do_homepage, "homepage")

    # Step 2: WHOIS lookup
    step("WHOIS lookup", lambda: whois_lookup(domain), "whois")

    # Step 3: DNS enumeration
    step("DNS enumeration", lambda: dns_full_enumeration(domain), "dns")

    # Step 4: TLS certificate analysis
    step("TLS certificate analysis", lambda: tls_cert_analysis(domain), "tls")

    # Step 5: IP analysis (reverse IP + ASN for each IP)
    def do_ip_analysis():
        dns_data = None
        with intel_lock:
            dom_data = intel_db["domains"].get(domain, {})
            dns_cat = dom_data.get("categories", {}).get("dns", {})
            dns_data = dns_cat.get("data", {})
        ips = dns_data.get("infrastructure", {}).get("ips", []) if dns_data else []
        ip_results = []
        for ip in ips[:5]:  # Limit to first 5 IPs
            rev = reverse_ip_lookup(ip, ua)
            info = ip_info_lookup(ip, ua)
            ip_results.append({
                "ip": ip,
                "reverse_domains": rev.get("domains", [])[:50],
                "reverse_count": rev.get("count", len(rev.get("domains", []))),
                "asn": info.get("asn"),
                "asn_name": info.get("asn_name"),
                "org": info.get("org"),
                "isp": info.get("isp"),
                "geo": info.get("geo"),
            })
        return ip_results

    step("IP & hosting analysis", do_ip_analysis, "ip_analysis")

    # Step 6: Reverse DNS on IPs
    def do_reverse_dns():
        dns_data = None
        with intel_lock:
            dom_data = intel_db["domains"].get(domain, {})
            dns_cat = dom_data.get("categories", {}).get("dns", {})
            dns_data = dns_cat.get("data", {})
        ips = dns_data.get("infrastructure", {}).get("ips", []) if dns_data else []
        results = []
        for ip in ips[:5]:
            results.append(dns_reverse_lookup(ip))
        return results

    step("Reverse DNS", do_reverse_dns, "reverse_dns")

    # Step 7: Check for related domains via CT logs
    def do_ct_related():
        from collections import Counter
        # Use existing passive discovery to find subdomains
        subs, _ = passive_subdomain_discovery(domain)
        # Also look at TLS SANs for related root domains
        related_roots = set()
        with intel_lock:
            dom_data = intel_db["domains"].get(domain, {})
            tls_data = dom_data.get("categories", {}).get("tls", {}).get("data", {})
        for san in tls_data.get("san_domains", []):
            san = san.lstrip("*.")
            parts = san.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])
                if root != domain:
                    related_roots.add(root)
        return {
            "subdomains_found": len(subs),
            "subdomains": sorted(subs)[:100],
            "related_root_domains": sorted(related_roots),
        }

    step("CT log & related domain analysis", do_ct_related, "ct_related")

    # Step 8: Passive vulnerability assessment
    def do_vuln_assessment():
        tech_data = None
        headers_data = None
        with intel_lock:
            dom_data = intel_db["domains"].get(domain, {}).get("categories", {})
            if "tech" in dom_data:
                tech_data = dom_data["tech"].get("data", {})
        return run_vulnerability_assessment(domain, tech_data, headers_data)

    step("Passive vulnerability assessment", do_vuln_assessment, "vuln_assessment")

    # Step 9: Run correlations
    def do_correlations():
        return find_correlations()

    step("Building correlations", do_correlations, "correlations_result")

    with intel_lock:
        intel_state["active"] = False
        intel_state["status"] = "complete"

    logger.info(f"Investigation complete for {domain}")



# --- Intel API Endpoints ---

@app.route("/api/intel/investigate", methods=["POST"])
def start_investigation():
    if intel_state["active"]:
        return jsonify({"error": "Investigation already running"}), 409
    data = request.json
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    thread = threading.Thread(target=run_investigation, args=(domain,), daemon=True)
    thread.start()
    return jsonify({"ok": True, "domain": domain})


@app.route("/api/intel/status", methods=["GET"])
def intel_status_endpoint():
    with intel_lock:
        return jsonify({
            "active": intel_state["active"],
            "domain": intel_state.get("domain"),
            "progress": intel_state.get("progress", 0),
            "total": intel_state.get("total", 8),
            "status": intel_state.get("status", "idle"),
            "steps_completed": intel_state.get("steps_completed", []),
        })


@app.route("/api/intel/cancel", methods=["POST"])
def cancel_investigation():
    with intel_lock:
        intel_state["cancel_requested"] = True
    return jsonify({"ok": True})


@app.route("/api/intel/results/<domain>", methods=["GET"])
def get_domain_intel(domain):
    with intel_lock:
        dom_data = intel_db["domains"].get(domain)
    if not dom_data:
        return jsonify({"error": "No intel for this domain"}), 404
    result = {"domain": domain, "first_seen": dom_data.get("first_seen")}
    for cat_name, cat_data in dom_data.get("categories", {}).items():
        result[cat_name] = cat_data.get("data")
    return jsonify(result)


@app.route("/api/intel/domains", methods=["GET"])
def list_investigated_domains():
    with intel_lock:
        domains = []
        for domain, info in intel_db["domains"].items():
            domains.append({
                "domain": domain,
                "first_seen": info.get("first_seen"),
                "categories": list(info.get("categories", {}).keys()),
            })
    return jsonify({"domains": domains})


@app.route("/api/intel/correlations", methods=["GET"])
def get_correlations():
    with intel_lock:
        corrs = intel_db["correlations"]
    return jsonify({"correlations": corrs, "count": len(corrs)})


@app.route("/api/intel/graph", methods=["GET"])
def get_graph():
    graph = build_graph_data()
    return jsonify(graph)


@app.route("/api/intel/whois", methods=["POST"])
def whois_endpoint():
    data = request.json
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    result = whois_lookup(domain)
    store_domain_intel(domain, "whois", result)
    return jsonify(result)


@app.route("/api/intel/dns", methods=["POST"])
def dns_endpoint():
    data = request.json
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    result = dns_full_enumeration(domain)
    store_domain_intel(domain, "dns", result)
    return jsonify(result)


@app.route("/api/intel/tls", methods=["POST"])
def tls_endpoint():
    data = request.json
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    result = tls_cert_analysis(domain)
    store_domain_intel(domain, "tls", result)
    return jsonify(result)


@app.route("/api/intel/reverse-ip", methods=["POST"])
def reverse_ip_endpoint():
    data = request.json
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    ua = settings.get("user_agent", "Ariadne/1.0")
    result = reverse_ip_lookup(ip, ua)
    info = ip_info_lookup(ip, ua)
    result["asn"] = info.get("asn")
    result["asn_name"] = info.get("asn_name")
    result["org"] = info.get("org")
    result["geo"] = info.get("geo")
    return jsonify(result)


@app.route("/api/intel/analyze-url", methods=["POST"])
def analyze_url_endpoint():
    data = request.json
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith("http"):
        url = "https://" + url
    session = create_session()
    try:
        resp = session.get(url, timeout=15, allow_redirects=True, proxies=get_proxy())
        html = resp.text
        headers = dict(resp.headers)
        return jsonify({
            "url": url,
            "status_code": resp.status_code,
            "analytics": extract_analytics_ids(html),
            "tech": extract_tech_fingerprint(html, headers, url),
            "social": extract_social_contacts(html),
            "favicon": compute_favicon_hash(session, url),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/intel/clear", methods=["POST"])
def clear_intel():
    with intel_lock:
        intel_db["domains"] = {}
        intel_db["correlations"] = []
    return jsonify({"ok": True})


@app.route("/api/intel/remove/<domain>", methods=["DELETE"])
def remove_domain_intel(domain):
    with intel_lock:
        if domain in intel_db["domains"]:
            del intel_db["domains"][domain]
            find_correlations()
    return jsonify({"ok": True})



# ─── Passive Vulnerability Assessment ───────────────────────────────────────

# Known software EOL dates and version ranges
# Format: product -> [(version_prefix, eol_date, note)]
SOFTWARE_EOL = {
    "PHP": [
        ("5.", "2018-12-31", "PHP 5.x is end-of-life since Dec 2018"),
        ("7.0", "2019-01-10", "PHP 7.0 EOL Jan 2019"),
        ("7.1", "2019-12-01", "PHP 7.1 EOL Dec 2019"),
        ("7.2", "2020-11-30", "PHP 7.2 EOL Nov 2020"),
        ("7.3", "2021-12-06", "PHP 7.3 EOL Dec 2021"),
        ("7.4", "2022-11-28", "PHP 7.4 EOL Nov 2022"),
        ("8.0", "2023-11-26", "PHP 8.0 EOL Nov 2023"),
        ("8.1", "2025-12-31", "PHP 8.1 EOL Dec 2025"),
    ],
    "Apache": [
        ("2.2", "2018-01-01", "Apache 2.2 is end-of-life"),
        ("2.0", "2013-07-10", "Apache 2.0 is end-of-life"),
    ],
    "Nginx": [
        ("1.0", "2016-04-26", "Nginx 1.0.x is very outdated"),
        ("1.2", "2016-04-26", "Nginx 1.2.x is very outdated"),
        ("1.4", "2016-04-26", "Nginx 1.4.x is very outdated"),
    ],
    "WordPress": [
        ("3.", "2019-01-01", "WordPress 3.x is end-of-life"),
        ("4.", "2022-01-01", "WordPress 4.x is end-of-life"),
        ("5.0", "2022-01-01", "WordPress 5.0-5.2 no longer receives updates"),
        ("5.1", "2022-01-01", "WordPress 5.1 no longer receives updates"),
        ("5.2", "2022-01-01", "WordPress 5.2 no longer receives updates"),
    ],
    "jQuery": [
        ("1.", "2019-01-01", "jQuery 1.x is end-of-life and has known XSS vulnerabilities"),
        ("2.", "2019-01-01", "jQuery 2.x is end-of-life"),
    ],
    "IIS": [
        ("6.", "2015-07-14", "IIS 6 (Windows Server 2003) is end-of-life"),
        ("7.", "2020-01-14", "IIS 7/7.5 (Server 2008) is end-of-life"),
        ("8.", "2023-10-10", "IIS 8/8.5 (Server 2012) is end-of-life"),
    ],
    "Drupal": [
        ("7.", "2025-01-05", "Drupal 7 reached end-of-life Jan 2025"),
        ("8.", "2021-11-02", "Drupal 8 reached end-of-life Nov 2021"),
    ],
    "Joomla": [
        ("1.", "2014-01-01", "Joomla 1.x is end-of-life"),
        ("2.", "2014-01-01", "Joomla 2.x is end-of-life"),
        ("3.", "2023-08-17", "Joomla 3.x reached end-of-life Aug 2023"),
    ],
    "Angular": [
        ("1.", "2022-01-01", "AngularJS 1.x reached end-of-life Dec 2021"),
    ],
    "Bootstrap": [
        ("2.", "2019-01-01", "Bootstrap 2.x is very outdated"),
        ("3.", "2023-01-01", "Bootstrap 3.x is end-of-life"),
    ],
}

# Sensitive paths to check via HEAD request (non-intrusive)
EXPOSED_PATHS = [
    # Version control
    {"path": "/.git/config", "severity": "critical", "category": "Version Control",
     "description": "Git repository configuration exposed - may leak source code"},
    {"path": "/.git/HEAD", "severity": "critical", "category": "Version Control",
     "description": "Git repository HEAD exposed - source code is likely accessible"},
    {"path": "/.svn/entries", "severity": "critical", "category": "Version Control",
     "description": "SVN repository entries exposed"},
    {"path": "/.hg/store/00manifest.i", "severity": "high", "category": "Version Control",
     "description": "Mercurial repository exposed"},

    # Environment and config files
    {"path": "/.env", "severity": "critical", "category": "Configuration",
     "description": "Environment file exposed - may contain database passwords, API keys, secrets"},
    {"path": "/.env.bak", "severity": "critical", "category": "Configuration",
     "description": "Backup environment file exposed"},
    {"path": "/config.php.bak", "severity": "high", "category": "Configuration",
     "description": "PHP config backup exposed"},
    {"path": "/wp-config.php.bak", "severity": "critical", "category": "Configuration",
     "description": "WordPress config backup exposed - contains database credentials"},
    {"path": "/web.config", "severity": "medium", "category": "Configuration",
     "description": "IIS web.config accessible"},
    {"path": "/.htaccess", "severity": "low", "category": "Configuration",
     "description": "Apache .htaccess file accessible"},

    # Database and backup files
    {"path": "/database.sql", "severity": "critical", "category": "Database",
     "description": "SQL database dump exposed"},
    {"path": "/db.sql", "severity": "critical", "category": "Database",
     "description": "SQL database dump exposed"},
    {"path": "/backup.sql", "severity": "critical", "category": "Database",
     "description": "SQL backup file exposed"},
    {"path": "/dump.sql", "severity": "critical", "category": "Database",
     "description": "SQL dump file exposed"},
    {"path": "/backup.zip", "severity": "high", "category": "Backup",
     "description": "Backup archive exposed"},
    {"path": "/backup.tar.gz", "severity": "high", "category": "Backup",
     "description": "Backup archive exposed"},

    # Admin and debug interfaces
    {"path": "/phpmyadmin/", "severity": "high", "category": "Admin Panel",
     "description": "phpMyAdmin accessible - database management interface"},
    {"path": "/adminer.php", "severity": "high", "category": "Admin Panel",
     "description": "Adminer database tool accessible"},
    {"path": "/wp-admin/install.php", "severity": "high", "category": "Admin Panel",
     "description": "WordPress installer still accessible"},
    {"path": "/server-status", "severity": "medium", "category": "Debug",
     "description": "Apache server-status page accessible"},
    {"path": "/server-info", "severity": "medium", "category": "Debug",
     "description": "Apache server-info page accessible"},
    {"path": "/debug/", "severity": "medium", "category": "Debug",
     "description": "Debug endpoint accessible"},
    {"path": "/elmah.axd", "severity": "medium", "category": "Debug",
     "description": "ASP.NET error log viewer accessible"},
    {"path": "/phpinfo.php", "severity": "medium", "category": "Debug",
     "description": "PHP info page exposed - reveals server configuration details"},

    # Information disclosure
    {"path": "/crossdomain.xml", "severity": "low", "category": "Information",
     "description": "Flash crossdomain policy file - may allow cross-origin access"},
    {"path": "/clientaccesspolicy.xml", "severity": "low", "category": "Information",
     "description": "Silverlight client access policy - may allow cross-origin access"},
    {"path": "/security.txt", "severity": "info", "category": "Information",
     "description": "Security contact information available (this is good practice)"},
    {"path": "/.well-known/security.txt", "severity": "info", "category": "Information",
     "description": "Security contact information available (this is good practice)"},
    {"path": "/humans.txt", "severity": "info", "category": "Information",
     "description": "humans.txt found - may reveal team member names"},
    {"path": "/readme.html", "severity": "low", "category": "Information",
     "description": "CMS readme file exposed - reveals exact version"},
    {"path": "/CHANGELOG.md", "severity": "low", "category": "Information",
     "description": "Changelog exposed - reveals version history"},
    {"path": "/license.txt", "severity": "info", "category": "Information",
     "description": "License file found - may help identify software version"},
]

# TLS cipher suite quality ratings
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


def nvd_cve_lookup(product, version, ua="Ariadne/1.0"):
    """Query NIST NVD API for known CVEs affecting a product+version.
    
    Uses the NVD 2.0 API (free, no key required but rate-limited).
    Without API key: ~5 requests per 30 seconds.
    """
    if not version:
        return []

    cves = []
    # Build search keyword - NVD keyword search is best-effort
    keyword = f"{product} {version}"
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": keyword,
                "resultsPerPage": 10,
            },
            timeout=20,
            headers={"User-Agent": ua},
        )
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract CVSS score
                cvss_score = None
                cvss_severity = None
                metrics = cve.get("metrics", {})
                # Try CVSS 3.1 first, then 3.0, then 2.0
                for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if cvss_key in metrics and metrics[cvss_key]:
                        cvss_data = metrics[cvss_key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity",
                                        metrics[cvss_key][0].get("baseSeverity"))
                        break

                # Extract description
                descriptions = cve.get("descriptions", [])
                desc_en = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_en = d.get("value", "")[:300]
                        break

                # Published date
                published = cve.get("published", "")[:10]

                if cve_id:
                    cves.append({
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": (cvss_severity or "").upper(),
                        "description": desc_en,
                        "published": published,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })

        elif resp.status_code == 403:
            logger.warning("NVD API rate limited - try again later or add API key")
            return [{"error": "NVD rate limited", "retry": True}]
        else:
            logger.warning(f"NVD API returned {resp.status_code}")
    except Exception as e:
        logger.warning(f"NVD lookup failed for {keyword}: {e}")

    # Sort by CVSS score descending
    cves.sort(key=lambda x: -(x.get("cvss_score") or 0))
    return cves[:10]  # Return top 10


def check_eol_software(tech_dict):
    """Check detected technologies against known EOL dates."""
    findings = []
    for tech_name, version in tech_dict.items():
        if not version or tech_name not in SOFTWARE_EOL:
            continue
        for prefix, eol_date, note in SOFTWARE_EOL[tech_name]:
            if version.startswith(prefix):
                findings.append({
                    "technology": tech_name,
                    "version": version,
                    "eol_date": eol_date,
                    "severity": "high",
                    "description": note,
                })
                break
    return findings


def grade_security_headers(headers_dict):
    """Score security headers with a letter grade and detailed findings."""
    # Define all headers to check with their weight and ideal values
    header_checks = {
        "Strict-Transport-Security": {
            "weight": 15, "required": True,
            "check": lambda v: (
                10 if "max-age=" in v and int(re.search(r"max-age=(\d+)", v).group(1) if re.search(r"max-age=(\d+)", v) else "0") >= 31536000 else 5,
                "max-age should be at least 31536000 (1 year)" if "max-age=" not in v or int(re.search(r"max-age=(\d+)", v).group(1) if re.search(r"max-age=(\d+)", v) else "0") < 31536000 else
                ("includeSubDomains recommended" if "includeSubDomains" not in v else None)
            ),
        },
        "Content-Security-Policy": {
            "weight": 20, "required": True,
            "check": lambda v: (
                5 if "unsafe-inline" in v or "unsafe-eval" in v else 10,
                "CSP contains unsafe-inline or unsafe-eval" if "unsafe-inline" in v or "unsafe-eval" in v else None
            ),
        },
        "X-Content-Type-Options": {
            "weight": 10, "required": True,
            "check": lambda v: (10 if v.lower() == "nosniff" else 5, None if v.lower() == "nosniff" else "Should be 'nosniff'"),
        },
        "X-Frame-Options": {
            "weight": 10, "required": True,
            "check": lambda v: (10 if v.upper() in ("DENY", "SAMEORIGIN") else 5, None),
        },
        "Referrer-Policy": {
            "weight": 8, "required": False,
            "check": lambda v: (
                10 if v.lower() in ("no-referrer", "strict-origin-when-cross-origin", "strict-origin", "same-origin", "no-referrer-when-downgrade") else 5,
                None if v.lower() != "unsafe-url" else "unsafe-url leaks full URL to third parties"
            ),
        },
        "Permissions-Policy": {
            "weight": 8, "required": False,
            "check": lambda v: (10, None),
        },
        "Cross-Origin-Opener-Policy": {
            "weight": 5, "required": False,
            "check": lambda v: (10, None),
        },
        "Cross-Origin-Resource-Policy": {
            "weight": 5, "required": False,
            "check": lambda v: (10, None),
        },
        "Cross-Origin-Embedder-Policy": {
            "weight": 4, "required": False,
            "check": lambda v: (10, None),
        },
        "X-XSS-Protection": {
            "weight": 3, "required": False,
            "check": lambda v: (
                10 if "1" in v and "mode=block" in v else 7 if "1" in v else 3,
                "Deprecated but '1; mode=block' is still a good fallback" if "mode=block" not in v else None
            ),
        },
        "X-Permitted-Cross-Domain-Policies": {
            "weight": 2, "required": False,
            "check": lambda v: (10, None),
        },
    }

    headers_lower = {k.lower(): v for k, v in headers_dict.items()}
    total_weight = sum(h["weight"] for h in header_checks.values())
    earned = 0
    findings = []
    present_headers = []
    missing_headers = []

    for header_name, spec in header_checks.items():
        val = headers_lower.get(header_name.lower())
        if val:
            present_headers.append(header_name)
            try:
                score, note = spec["check"](val)
                earned += (score / 10) * spec["weight"]
                if note:
                    findings.append({
                        "header": header_name,
                        "severity": "medium",
                        "finding": note,
                        "value": val[:200],
                    })
            except Exception:
                earned += spec["weight"] * 0.5
        else:
            missing_headers.append(header_name)
            if spec["required"]:
                findings.append({
                    "header": header_name,
                    "severity": "high" if spec["weight"] >= 10 else "medium",
                    "finding": f"Missing required security header: {header_name}",
                    "value": None,
                })

    # Check for information-leaking headers
    leaky_headers = {
        "Server": "Reveals web server software and version",
        "X-Powered-By": "Reveals backend technology",
        "X-AspNet-Version": "Reveals ASP.NET version",
        "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
    }
    for h_name, h_desc in leaky_headers.items():
        if headers_lower.get(h_name.lower()):
            findings.append({
                "header": h_name,
                "severity": "low",
                "finding": f"Information disclosure: {h_desc}",
                "value": headers_lower[h_name.lower()][:100],
            })

    # Calculate percentage and letter grade
    pct = round((earned / total_weight) * 100) if total_weight > 0 else 0
    if pct >= 90: grade = "A+"
    elif pct >= 80: grade = "A"
    elif pct >= 70: grade = "B"
    elif pct >= 60: grade = "C"
    elif pct >= 50: grade = "D"
    else: grade = "F"

    return {
        "grade": grade,
        "score": pct,
        "present": present_headers,
        "missing": missing_headers,
        "findings": findings,
        "total_checked": len(header_checks),
    }


def assess_tls_config(domain, port=443):
    """Assess TLS/SSL configuration strength."""
    findings = []
    protocols_supported = []
    cipher_info = None
    cert_issues = []

    # Check which TLS versions are supported
    protocol_map = {
        "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None,
    }

    for proto_name, proto_ver in protocol_map.items():
        if proto_ver is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_ver
            ctx.maximum_version = proto_ver
            conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
            conn.settimeout(5)
            conn.connect((domain, port))
            protocols_supported.append(proto_name)
            conn.close()
        except Exception:
            pass

    # Flag weak protocols
    for wp in WEAK_PROTOCOLS:
        if wp in protocols_supported:
            findings.append({
                "severity": "high" if wp in ("SSLv2", "SSLv3") else "medium",
                "category": "Protocol",
                "finding": f"Weak protocol {wp} is supported",
                "recommendation": f"Disable {wp} - only TLSv1.2+ should be enabled",
            })

    if "TLSv1.3" not in protocols_supported:
        findings.append({
            "severity": "low",
            "category": "Protocol",
            "finding": "TLS 1.3 is not supported",
            "recommendation": "Enable TLS 1.3 for best performance and security",
        })

    # Get cipher suite on the best connection
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, port))
        cipher_info = conn.cipher()  # (name, version, bits)
        cert = conn.getpeercert()

        # Check cipher strength
        if cipher_info:
            cipher_name, _, bits = cipher_info
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    findings.append({
                        "severity": "high",
                        "category": "Cipher",
                        "finding": f"Weak cipher suite negotiated: {cipher_name}",
                        "recommendation": "Disable weak cipher suites",
                    })
                    break
            if bits and bits < 128:
                findings.append({
                    "severity": "high",
                    "category": "Cipher",
                    "finding": f"Cipher uses only {bits}-bit encryption",
                    "recommendation": "Minimum 128-bit encryption recommended",
                })

        # Check certificate validity period
        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    from email.utils import parsedate_to_datetime
                    expiry = parsedate_to_datetime(not_after)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        cert_issues.append({
                            "severity": "critical",
                            "finding": f"Certificate expired {abs(days_left)} days ago",
                        })
                    elif days_left < 14:
                        cert_issues.append({
                            "severity": "high",
                            "finding": f"Certificate expires in {days_left} days",
                        })
                    elif days_left < 30:
                        cert_issues.append({
                            "severity": "medium",
                            "finding": f"Certificate expires in {days_left} days",
                        })
                except Exception:
                    pass

            # Check for wildcard cert
            san_list = cert.get("subjectAltName", ())
            for san_type, san_val in san_list:
                if san_val.startswith("*."):
                    cert_issues.append({
                        "severity": "info",
                        "finding": f"Wildcard certificate in use: {san_val}",
                    })
                    break

        conn.close()
    except ssl.SSLCertVerificationError as e:
        cert_issues.append({
            "severity": "critical",
            "finding": f"Certificate verification failed: {str(e)[:200]}",
        })
    except Exception as e:
        findings.append({
            "severity": "high",
            "category": "Connection",
            "finding": f"TLS connection failed: {str(e)[:200]}",
            "recommendation": "Check if the server supports modern TLS",
        })

    # HSTS preload check
    try:
        resp = requests.head(f"https://{domain}", timeout=10, allow_redirects=True)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            findings.append({
                "severity": "medium",
                "category": "HSTS",
                "finding": "HSTS header not set",
                "recommendation": "Add Strict-Transport-Security header with includeSubDomains and preload",
            })
        else:
            if "preload" not in hsts:
                findings.append({
                    "severity": "low",
                    "category": "HSTS",
                    "finding": "HSTS preload directive not set",
                    "recommendation": "Add 'preload' to HSTS header and submit to hstspreload.org",
                })
    except Exception:
        pass

    # Calculate grade
    crit = sum(1 for f in findings + cert_issues if f.get("severity") == "critical")
    high = sum(1 for f in findings + cert_issues if f.get("severity") == "high")
    med = sum(1 for f in findings + cert_issues if f.get("severity") == "medium")

    if crit > 0: grade = "F"
    elif high > 1: grade = "D"
    elif high == 1: grade = "C"
    elif med > 1: grade = "B"
    elif med == 1: grade = "A"
    else: grade = "A+"

    return {
        "domain": domain,
        "grade": grade,
        "protocols": protocols_supported,
        "cipher": {
            "name": cipher_info[0] if cipher_info else None,
            "version": cipher_info[1] if cipher_info else None,
            "bits": cipher_info[2] if cipher_info else None,
        },
        "cert_issues": cert_issues,
        "findings": findings,
    }


def check_exposed_paths(domain, session=None, ua="Ariadne/1.0"):
    """Check for commonly exposed sensitive paths using HEAD requests only.

    HEAD requests are identical to what any web browser does — we only
    look at status codes and Content-Type, never send payloads.
    """
    if session is None:
        session = create_session()

    base_url = f"https://{domain}"
    results = []

    for entry in EXPOSED_PATHS:
        url = base_url + entry["path"]
        try:
            resp = session.head(url, timeout=8, allow_redirects=True,
                               headers={"User-Agent": ua}, proxies=get_proxy())

            # A 200 or 403 (forbidden but exists) is interesting
            # 404, 301 to homepage, etc. are not
            is_found = False
            if resp.status_code == 200:
                # Verify it's not just a generic 200 (soft 404)
                ct = resp.headers.get("Content-Type", "")
                cl = resp.headers.get("Content-Length", "0")
                # If it returns HTML with a small size, likely a custom 404
                if "text/html" in ct and int(cl or "0") < 500 and entry["severity"] != "info":
                    continue
                is_found = True
            elif resp.status_code == 403:
                # Forbidden = exists but access denied, still notable for some paths
                if entry["severity"] in ("critical", "high"):
                    is_found = True

            if is_found:
                results.append({
                    "path": entry["path"],
                    "status_code": resp.status_code,
                    "severity": entry["severity"],
                    "category": entry["category"],
                    "description": entry["description"],
                    "content_type": resp.headers.get("Content-Type", ""),
                    "content_length": resp.headers.get("Content-Length"),
                })
        except Exception:
            pass

        # Small delay to be respectful
        time.sleep(0.15)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return results


def run_vulnerability_assessment(domain, tech_dict=None, headers_dict=None):
    """Run complete passive vulnerability assessment.

    Combines: CVE lookup, EOL detection, header grading, TLS assessment,
    and exposed path detection into a single report.
    """
    ua = settings.get("user_agent", "Ariadne/1.0")
    session = create_session()
    report = {
        "domain": domain,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "cve_results": [],
        "eol_findings": [],
        "header_grade": None,
        "tls_grade": None,
        "exposed_paths": [],
        "overall_grade": None,
    }

    # 1. If we don't have tech data, fetch the homepage
    if not tech_dict or not headers_dict:
        try:
            resp = session.get(f"https://{domain}", timeout=15,
                             allow_redirects=True, proxies=get_proxy())
            html = resp.text
            raw_headers = dict(resp.headers)
            if not tech_dict:
                tech_dict = extract_tech_fingerprint(html, raw_headers,
                                                     f"https://{domain}")
            if not headers_dict:
                headers_dict = raw_headers
        except Exception as e:
            logger.warning(f"Vuln assessment: could not fetch {domain}: {e}")
            if not tech_dict:
                tech_dict = {}
            if not headers_dict:
                headers_dict = {}

    # 2. CVE lookup for detected technologies with versions
    cve_results = {}
    for tech_name, version in tech_dict.items():
        if version:
            logger.info(f"Vuln: NVD lookup for {tech_name} {version}")
            cves = nvd_cve_lookup(tech_name, version, ua)
            if cves and not (len(cves) == 1 and "error" in cves[0]):
                cve_results[f"{tech_name} {version}"] = cves
            # NVD rate limit: pause between requests
            time.sleep(6.5)
    report["cve_results"] = cve_results

    # 3. EOL software detection
    report["eol_findings"] = check_eol_software(tech_dict)

    # 4. Security header grading
    report["header_grade"] = grade_security_headers(headers_dict)

    # 5. TLS configuration assessment
    try:
        report["tls_grade"] = assess_tls_config(domain)
    except Exception as e:
        report["tls_grade"] = {"domain": domain, "grade": "?", "error": str(e)}

    # 6. Exposed path detection
    report["exposed_paths"] = check_exposed_paths(domain, session, ua)

    # Count totals
    all_findings = []
    # From CVEs
    for tech, cves in cve_results.items():
        for cve in cves:
            sev = (cve.get("severity") or "MEDIUM").lower()
            if sev == "critical": report["summary"]["critical"] += 1
            elif sev == "high": report["summary"]["high"] += 1
            elif sev == "medium": report["summary"]["medium"] += 1
            elif sev == "low": report["summary"]["low"] += 1
    # From EOL
    for f in report["eol_findings"]:
        report["summary"]["high"] += 1
    # From headers
    if report["header_grade"]:
        for f in report["header_grade"].get("findings", []):
            sev = f.get("severity", "low")
            report["summary"][sev] = report["summary"].get(sev, 0) + 1
    # From TLS
    if report["tls_grade"]:
        for f in report["tls_grade"].get("findings", []):
            sev = f.get("severity", "low")
            report["summary"][sev] = report["summary"].get(sev, 0) + 1
        for f in report["tls_grade"].get("cert_issues", []):
            sev = f.get("severity", "low")
            report["summary"][sev] = report["summary"].get(sev, 0) + 1
    # From exposed paths
    for f in report["exposed_paths"]:
        sev = f.get("severity", "low")
        report["summary"][sev] = report["summary"].get(sev, 0) + 1

    # Overall grade
    s = report["summary"]
    if s["critical"] > 0: report["overall_grade"] = "F"
    elif s["high"] > 2: report["overall_grade"] = "D"
    elif s["high"] > 0: report["overall_grade"] = "C"
    elif s["medium"] > 3: report["overall_grade"] = "C"
    elif s["medium"] > 0: report["overall_grade"] = "B"
    elif s["low"] > 2: report["overall_grade"] = "A"
    else: report["overall_grade"] = "A+"

    return report



@app.route('/api/intel/vuln-assess', methods=['POST'])
def vuln_assess_endpoint():
    data = request.json
    domain = data.get('domain', '').strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    tech_dict = None
    headers_dict = None
    with intel_lock:
        dom_data = intel_db['domains'].get(domain, {}).get('categories', {})
        if 'tech' in dom_data:
            tech_dict = dom_data['tech'].get('data', {})
    report = run_vulnerability_assessment(domain, tech_dict, headers_dict)
    store_domain_intel(domain, 'vuln_assessment', report)
    return jsonify(report)


@app.route('/api/intel/vuln-results/<domain>', methods=['GET'])
def vuln_results_endpoint(domain):
    with intel_lock:
        dom_data = intel_db['domains'].get(domain, {})
        vuln = dom_data.get('categories', {}).get('vuln_assessment', {}).get('data')
    if not vuln:
        return jsonify({'error': 'No vulnerability assessment for this domain'}), 404
    return jsonify(vuln)


@app.route('/api/intel/header-grade', methods=['POST'])
def header_grade_endpoint():
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        session = create_session()
        resp = session.get(url, timeout=15, allow_redirects=True, proxies=get_proxy())
        grade = grade_security_headers(dict(resp.headers))
        return jsonify(grade)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/intel/tls-grade', methods=['POST'])
def tls_grade_endpoint():
    data = request.json
    domain = data.get('domain', '').strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    try:
        result = assess_tls_config(domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/intel/exposed-paths', methods=['POST'])
def exposed_paths_endpoint():
    data = request.json
    domain = data.get('domain', '').strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    ua = settings.get('user_agent', 'Ariadne/1.0')
    results = check_exposed_paths(domain, ua=ua)
    return jsonify({'domain': domain, 'results': results, 'count': len(results)})


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Ariadne starting on http://127.0.0.1:{port}")
    save_settings(settings)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
