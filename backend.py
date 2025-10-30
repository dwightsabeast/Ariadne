import re
import requests
import socket
import time
from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import dns.resolver
import dns.reversename
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import xml.etree.ElementTree as ET
import json
import whois 
import itertools
import urllib3
import difflib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime, timezone
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string
from googlesearch import search
import ipaddress
import os
import base64
import mimetypes
from werkzeug.utils import secure_filename

# NEW: Import selenium-stealth
try:
    from selenium_stealth import stealth
except ImportError:
    print("selenium-stealth not found. Run 'pip install selenium-stealth'. Bot detection may fail.")
    stealth = None

try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    print("SOCKS proxy support is not available. Please install 'pysocks'.")
    SOCKSProxyManager = None

# --- Custom DNS Resolver ---
# Explicitly configure a resolver to use reliable public DNS servers.
# This avoids issues with local/system resolvers that may fail or time out.
my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
my_resolver.timeout = 5.0  # Set a reasonable timeout
my_resolver.lifetime = 5.0 # Set a reasonable lifetime
# --- End Custom DNS Resolver ---


# Suppress only the single InsecureRequestWarning from urllib3 needed for this specific app
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__, static_url_path='', static_folder='.')
CORS(app)

# --- Global variables & Configuration ---
PROXY_LIST = []
PROXY_CYCLE = None
PROXIES_ENABLED = True
ARCHIVE_FOLDER = ""
AUTH_COOKIE = None # NEW: Global var for auth cookie
SETTINGS_FILE = 'settings.json'
SCHEDULES_FILE = 'schedules.json'
SUBDOMAIN_WORDLIST = 'subdomains.txt'
LAST_RESULTS_FILE = 'last_results.json'
LOCAL_ARCHIVES_DIR = 'local_archives'

# --- Scheduler Setup ---
scheduler = BackgroundScheduler()

def load_settings():
    """Loads settings from the settings file."""
    global PROXIES_ENABLED, ARCHIVE_FOLDER, AUTH_COOKIE
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
            PROXIES_ENABLED = settings.get('proxies_enabled', True)
            ARCHIVE_FOLDER = settings.get('archive_folder', "")
            
            # NEW: Load auth cookie settings
            cookie_domain = settings.get('cookie_domain')
            cookie_name = settings.get('cookie_name')
            cookie_value = settings.get('cookie_value')
            
            if cookie_domain and cookie_name and cookie_value:
                AUTH_COOKIE = {
                    'name': cookie_name,
                    'value': cookie_value,
                    'domain': cookie_domain
                }
                print(f"Authentication cookie loaded for domain: {cookie_domain}")
            else:
                AUTH_COOKIE = None

        print(f"Settings loaded: Proxies enabled -> {PROXIES_ENABLED}, Archive Folder -> '{ARCHIVE_FOLDER}'")
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"{SETTINGS_FILE} not found or invalid. Creating with default settings.")
        PROXIES_ENABLED = True
        ARCHIVE_FOLDER = ""
        AUTH_COOKIE = None
        save_settings() # Will save with default (empty) auth settings

def save_settings():
    """Saves the current settings to the settings file."""
    cookie_domain = AUTH_COOKIE['domain'] if AUTH_COOKIE else ""
    cookie_name = AUTH_COOKIE['name'] if AUTH_COOKIE else ""
    cookie_value = AUTH_COOKIE['value'] if AUTH_COOKIE else ""
    
    with open(SETTINGS_FILE, 'w') as f:
        json.dump({
            'proxies_enabled': PROXIES_ENABLED,
            'archive_folder': ARCHIVE_FOLDER,
            'cookie_domain': cookie_domain,
            'cookie_name': cookie_name,
            'cookie_value': cookie_value
        }, f, indent=4)
    print(f"Settings saved: Proxies enabled -> {PROXIES_ENABLED}, Archive Folder -> '{ARCHIVE_FOLDER}'")


def load_proxies():
    """Loads proxies from proxies.txt into the global proxy cycle."""
    global PROXY_LIST, PROXY_CYCLE
    try:
        with open('proxies.txt', 'r') as f:
            PROXY_LIST = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if PROXY_LIST:
            PROXY_CYCLE = itertools.cycle(PROXY_LIST)
            print(f"Successfully loaded {len(PROXY_LIST)} proxies.")
        else:
            print("proxies.txt is empty. Archiving will use your server's IP.")
            PROXY_CYCLE = None
    except FileNotFoundError:
        print("proxies.txt not found. Creating it.")
        with open('proxies.txt', 'w') as f:
            f.write("# Add proxy addresses here, one per line.\n")
        PROXY_LIST = []
        PROXY_CYCLE = None

# --- Core Logic Functions (Internal, for scheduler use) ---

def find_subdomains_internal(domain, brute_force=False):
    potential_subdomains = set()

    # --- DNS Zone Transfer (AXFR) Attempt ---
    print("Attempting DNS Zone Transfer (AXFR)...")
    try:
        ns_answers = my_resolver.resolve(domain, 'NS')
        for ns_server in ns_answers:
            try:
                ns_addr = my_resolver.resolve(ns_server.target, 'A')[0].to_text()
                zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain, timeout=5))
                for name, node in zone.nodes.items():
                    subdomain = f"{name}.{domain}"
                    potential_subdomains.add((subdomain, 'AXFR'))
                print(f"Zone transfer successful from {ns_server}!")
                break 
            except Exception as e:
                print(f"Zone transfer failed from {ns_server}: {e}")
                continue 
    except Exception as e:
        print(f"Could not get nameservers for AXFR attempt: {e}")


    # --- Passive Discovery ---
    # Site Crawl for links (using Selenium)
    driver = None
    try:
        print(f"Crawling https://{domain} with headless browser for subdomain links...")
        driver = get_chrome_driver(domain_for_cookie=domain) # Pass domain for cookie
        if driver:
            # Try both www and non-www
            for url_to_crawl in [f"https://www.{domain}", f"https://{domain}"]:
                try:
                    driver.get(url_to_crawl)
                    # --- Improved dynamic content scroll ---
                    # CHANGED: Wait for a specific element that indicates the *real* page loaded
                    try:
                        WebDriverWait(driver, 20).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, "body[id], body[class]")) # Wait for a body with any id or class
                        )
                    except TimeoutException:
                        print(f"Timeout waiting for main page content at {url_to_crawl}. Page might be static or challenge failed.")
                        # Proceed anyway, maybe it's a simple page
                    
                    last_height = driver.execute_script("return document.body.scrollHeight")
                    scroll_pause_time = 1.5 # Time to wait after each scroll
                    
                    while True:
                        # Scroll down to bottom
                        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                        
                        # Wait to load page
                        time.sleep(scroll_pause_time) 
                        
                        # Calculate new scroll height and compare with last scroll height
                        new_height = driver.execute_script("return document.body.scrollHeight")
                        if new_height == last_height:
                            break # Reached the bottom
                        last_height = new_height
                    # --- End of improved scroll ---
                    
                    soup = BeautifulSoup(driver.page_source, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        try:
                            hostname = urlparse(href).hostname
                            if hostname and hostname.endswith(domain) and hostname != domain:
                                potential_subdomains.add((hostname, 'Crawl'))
                        except Exception:
                            continue
                except Exception as e:
                    print(f"Could not crawl {url_to_crawl}: {e}")
    except Exception as e:
        print(f"Error crawling main site with browser: {e}")
    finally:
        if driver:
            driver.quit()

    # Google Search
    try:
        query = f"site:*.{domain}"
        for url in search(query, num_results=50):
            try:
                hostname = urlparse(url).hostname
                if hostname and hostname.endswith(domain) and hostname != domain:
                    potential_subdomains.add((hostname, 'Google'))
            except Exception:
                continue
    except Exception as e:
        print(f"Error querying Google: {e}")

    try:
        # ThreatCrowd API
        response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=15, verify=False)
        if response.ok:
            data = response.json()
            if data.get('subdomains'):
                for sub in data['subdomains']:
                    potential_subdomains.add((sub, 'ThreatCrowd'))
    except Exception as e:
        print(f"Error querying ThreatCrowd: {e}")

    try:
        # crt.sh - Increased timeout and include expired
        response = requests.get(f"https.crt.sh/?q=%.{domain}&output=json&exclude=expired", timeout=60, verify=False)
        if response.ok:
            certs = response.json()
            for cert in certs:
                name_value = cert.get('name_value')
                if name_value:
                    subdomains_from_cert = name_value.split('\n')
                    for sub in subdomains_from_cert:
                        clean_sub = sub.strip()
                        if clean_sub.endswith(f".{domain}") and '*' not in clean_sub and clean_sub != domain:
                            potential_subdomains.add((clean_sub, 'CT'))
    except Exception as e:
        print(f"Error querying crt.sh: {e}")

    # DNS lookups
    main_ips = set()
    for record_type in ['MX', 'NS', 'A']:
        try:
            answers = my_resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type in ['MX', 'NS']:
                    hostname = rdata.exchange.to_text().rstrip('.') if record_type == 'MX' else rdata.target.to_text().rstrip('.')
                    if hostname.endswith(domain) and hostname != domain:
                        potential_subdomains.add((hostname, record_type))
                elif record_type == 'A':
                    ip = rdata.to_text()
                    main_ips.add(ip)
                    try:
                        rev_name = dns.reversename.from_address(ip)
                        rev_answers = my_resolver.resolve(rev_name, "PTR")
                        for rev_rdata in rev_answers:
                            hostname = rev_rdata.to_text().rstrip('.')
                            if hostname.endswith(domain) and hostname != domain:
                                 potential_subdomains.add((hostname, 'PTR'))
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                        continue
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue

    # --- Reverse DNS on IP Blocks ---
    print("Performing Reverse DNS lookups on related IP blocks...")
    ip_nets_to_scan = {ipaddress.ip_network(f'{ip}/24', strict=False) for ip in main_ips}
    
    def reverse_dns_lookup(ip):
        try:
            rev_name = dns.reversename.from_address(str(ip))
            hostname = my_resolver.resolve(rev_name, "PTR")[0].to_text().rstrip('.')
            if hostname.endswith(domain):
                return (hostname, 'Rev-IP')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception:
            pass # Suppress other errors
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for net in ip_nets_to_scan:
            for ip in net.hosts():
                futures.append(executor.submit(reverse_dns_lookup, ip))
        for future in as_completed(futures):
            result = future.result()
            if result:
                potential_subdomains.add(result)
    print("Reverse DNS lookups complete.")


    # --- Unified Validation for all sources (Passive + Brute Force) ---
    all_subs_to_check = {sub[0] for sub in potential_subdomains}
    sources = {sub[0]: sub[1] for sub in potential_subdomains}

    if brute_force:
        print("Brute-force enabled, adding wordlist...")
        try:
            with open(SUBDOMAIN_WORDLIST, 'r') as f:
                wordlist = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            for word in wordlist:
                sub_name = f"{word}.{domain}"
                if sub_name not in all_subs_to_check:
                    all_subs_to_check.add(sub_name)
                    sources[sub_name] = 'Brute-Force'
        except FileNotFoundError:
            print(f"Warning: {SUBDOMAIN_WORDLIST} not found. Skipping brute-force.")

    print(f"Starting validation for {len(all_subs_to_check)} unique potential subdomains...")
    
    validated_subdomains = set()

    def check_subdomain(sub):
        try:
            my_resolver.resolve(sub, 'A')
            return (sub, sources.get(sub, 'Brute-Force'))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            try:
                # Fallback to check for CNAME record
                my_resolver.resolve(sub, 'CNAME')
                return (sub, sources.get(sub, 'CNAME'))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in all_subs_to_check}
        for future in as_completed(future_to_sub):
            result = future.result()
            if result:
                validated_subdomains.add(result)

    return [{"name": name, "type": type} for name, type in sorted(list(validated_subdomains))]


def check_diff_internal(url):
    try:
        full_url = normalize_url_for_requests(url)
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={full_url}&output=json&fl=timestamp&statuscode=200&limit=-1"
        cdx_response = requests.get(cdx_url, timeout=20)
        cdx_response.raise_for_status()
        snapshots = cdx_response.json()

        if len(snapshots) <= 1:
            return True # Not archived before, so it's a "change"

        latest_timestamp = snapshots[-1][0]
        archived_url = f"https://web.archive.org/web/{latest_timestamp}id_/{full_url}"
        
        archived_response = requests.get(archived_url, timeout=20)
        archived_soup = BeautifulSoup(archived_response.text, 'html.parser')
        archived_text = archived_soup.get_text()

        live_response = requests.get(full_url, timeout=20, verify=False)
        live_soup = BeautifulSoup(live_response.text, 'html.parser')
        live_text = live_soup.get_text()

        return archived_text != live_text
    except Exception as e:
        print(f"Scheduled scan: Error diffing {url}: {e}")
        return False # If diff fails, don't archive

def archive_url_internal(url):
    archive_api_url = f"https://web.archive.org/save/{url}"
    headers = {'User-Agent': 'Ariadne Scheduler/1.4'}
    
    if not PROXIES_ENABLED or not PROXY_LIST:
        try:
            http_manager = urllib3.PoolManager(headers=headers, cert_reqs='CERT_NONE')
            response = http_manager.request('GET', archive_api_url, timeout=30.0)
            if response.status < 400:
                print(f"Scheduled scan: Successfully archived {url} directly.")
        except Exception as e:
            print(f"Scheduled scan: Failed to archive {url} directly: {e}")
        return

    num_proxies = len(PROXY_LIST)
    for _ in range(num_proxies):
        proxy_line = next(PROXY_CYCLE).strip()
        if not re.match(r'^(http|https|socks4|socks5)://', proxy_line):
            proxy_line = 'socks5://' + proxy_line
        
        try:
            proxy_scheme = urlparse(proxy_line).scheme
            
            if proxy_scheme in ('socks4', 'socks5'):
                if SOCKSProxyManager is None:
                    raise ImportError("SOCKSProxyManager not available. 'pysocks' might be missing.")
                http_manager = SOCKSProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
            elif proxy_scheme in ('http', 'https'):
                http_manager = urllib3.ProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
            else:
                raise ValueError(f"Unsupported proxy scheme: {proxy_scheme}")

            response = http_manager.request('GET', archive_api_url, timeout=20.0)
            if response.status < 400:
                print(f"Scheduled scan: Successfully archived {url} using proxy {proxy_line}.")
                return # Success
        except Exception as e:
            print(f"Scheduled scan: Proxy {proxy_line} failed for {url}: {e}")
            continue
    print(f"Scheduled scan: All proxies failed for {url}.")

def run_scheduled_scan(domain):
    """The main function that the scheduler will execute."""
    print(f"--- Running scheduled scan for {domain} at {datetime.now()} ---")
    subdomains = find_subdomains_internal(domain, brute_force=True) # Always brute-force for scheduled scans
    if not subdomains:
        print(f"No subdomains found for {domain}. Scan complete.")
        return

    print(f"Found {len(subdomains)} subdomains. Checking each for changes...")
    for subdomain_info in subdomains:
        subdomain = subdomain_info['name']
        full_url = f"https://{subdomain}"
        print(f"Checking: {full_url}")
        if check_diff_internal(full_url):
            print(f"Changes detected for {full_url}. Archiving...")
            archive_url_internal(full_url)
            time.sleep(5) # Rate limit ourselves
        else:
            print(f"No changes for {full_url}. Skipping.")
    print(f"--- Scheduled scan for {domain} complete. ---")


# --- Helper Functions ---
def get_domain_name(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
            parsed_url = urlparse(url)
        
        domain = parsed_url.netloc.replace('www.', '')
        # Handle domain parts like .co.uk
        parts = domain.split('.')
        if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
             domain = '.'.join(parts[-3:])
        else:
             domain = '.'.join(parts[-2:])
        return domain
    except Exception as e:
        print(f"Error parsing domain from URL '{url}': {e}")
        return None

# MODIFIED: Added domain_for_cookie parameter
def get_chrome_driver(domain_for_cookie=None):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Add arguments to make Selenium less detectable
    chrome_options.add_argument("start-maximized")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
    except (WebDriverException, ValueError) as e:
        print(f"Could not start WebDriver via manager: {e}. Falling back to default PATH if possible.")
        try:
            driver = webdriver.Chrome(options=chrome_options)
        except WebDriverException as e_fallback:
            print(f"Fallback WebDriver initialization failed: {e_fallback}")
            return None

    # NEW: Apply selenium-stealth
    if stealth:
        stealth(driver,
                languages=["en-US", "en"],
                vendor="Google Inc.",
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
                )

    # NEW: Add auth cookie if it's set and matches the domain
    if AUTH_COOKIE and domain_for_cookie:
        # Check if the scan domain is a subdomain of the cookie domain
        if f".{domain_for_cookie}".endswith(AUTH_COOKIE['domain']):
            try:
                # Need to load a page in the domain *first* to set cookie
                temp_url = f"https://{domain_for_cookie.lstrip('.')}"
                driver.get(temp_url)
                driver.add_cookie(AUTH_COOKIE)
                print(f"Injected auth cookie for {domain_for_cookie}")
            except Exception as e:
                print(f"Warning: Could not set cookie for {domain_for_cookie}: {e}")
        else:
            print(f"Skipping cookie: Scan domain '{domain_for_cookie}' does not match cookie domain '{AUTH_COOKIE['domain']}'")


    return driver

def find_links_in_js(session, soup, base_url, domain, follow_external):
    js_links = set()
    try:
        # 'soup' is now passed in as an argument, no need to fetch/parse
        for script in soup.find_all('script', src=True):
            script_url = urljoin(base_url, script['src'])
            if follow_external or get_domain_name(script_url) == domain:
                try:
                    js_content = session.get(script_url, timeout=5, verify=False).text
                    paths = re.findall(r'[\'"](/[\w\d/.-]+)[\'"]', js_content)
                    for path in paths:
                        js_links.add(urljoin(base_url, path))
                except requests.RequestException as e:
                    print(f"Could not fetch JS file {script_url}: {e}")
    except requests.RequestException as e:
        print(f"Could not fetch base URL for JS scan {base_url}: {e}")
    except Exception as e:
        print(f"Error in find_links_in_js: {e}")
    return js_links

def normalize_url_for_requests(url):
    if not re.match(r'^[a-zA-Z]+://', url):
        return 'https://' + url
    return url

# --- Scheduling Persistence ---

def load_schedules():
    try:
        with open(SCHEDULES_FILE, 'r') as f:
            schedules = json.load(f)
            for job_info in schedules:
                scheduler.add_job(
                    run_scheduled_scan,
                    args=[job_info['domain']],
                    trigger=IntervalTrigger(
                        weeks=job_info.get('weeks') or 0, 
                        days=job_info.get('days') or 0
                    ),
                    id=job_info['id'],
                    name=job_info['domain'],
                    next_run_time=datetime.fromisoformat(job_info['next_run_time'])
                )
            print(f"Loaded {len(schedules)} schedules.")
    except (FileNotFoundError, json.JSONDecodeError):
        print("No schedules file found, starting fresh.")

# --- Web Server Endpoints ---

@app.route('/scan', methods=['GET'])
def scan_site():
    url = request.args.get('url')
    depth = int(request.args.get('depth', 1))
    follow_external = request.args.get('follow_external', 'false').lower() == 'true'

    if not url:
        return Response(stream_with_context('data: {"error": "URL is required"}\n\n'), mimetype='text/event-stream')

    base_domain = get_domain_name(url)
    if not base_domain:
        return Response(stream_with_context('data: {"error": "Invalid URL format"}\n\n'), mimetype='text/event-stream')

    def generate():
        def yield_event(data):
            return f"data: {json.dumps(data)}\n\n"

        all_links = set()
        
        # Site-based scans (like sitemap) will likely fail against bot protection
        # But we try anyway.
        yield yield_event({"status": "Checking for sitemap..."})
        try:
            # Use a session with a browser-like user agent
            sitemap_session = requests.Session()
            sitemap_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
            
            robots_url = urljoin(url, '/robots.txt')
            sitemap_urls = []
            try:
                r = sitemap_session.get(robots_url, timeout=10, verify=False)
                if r.ok:
                    for line in r.text.splitlines():
                        if line.lower().startswith('sitemap:'):
                            sitemap_urls.append(line.split(':', 1)[1].strip())
            except requests.RequestException as e:
                print(f"Could not fetch robots.txt: {e}")
                pass 
            
            if not sitemap_urls:
                sitemap_urls.append(urljoin(url, '/sitemap.xml'))

            for sitemap_url in sitemap_urls:
                try:
                    r = sitemap_session.get(sitemap_url, timeout=10, verify=False)
                    if r.ok:
                        yield yield_event({"status": f"Parsing sitemap: {sitemap_url}"})
                        tree = ET.fromstring(r.content)
                        for elem in tree.iterfind('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                            link = elem.text.strip()
                            if link and (follow_external or get_domain_name(link) == base_domain):
                                all_links.add(link)
                                yield yield_event({"link": link})
                except Exception as e:
                    print(f"Could not parse sitemap {sitemap_url}: {e}")
                    pass
        except Exception as e:
            print(f"Error during sitemap check: {e}")

        yield yield_event({"status": "Starting browser crawl..."})
        # Pass the base_domain to get_chrome_driver for cookie injection
        driver = get_chrome_driver(domain_for_cookie=base_domain)
        if not driver:
            yield yield_event({"error": "Could not initialize web driver."})
            yield "event: end\ndata: Scan finished\n\n"
            return
        
        to_visit = {url}
        visited = set()
        # Use a session for JS files, but it will fail if they are also protected
        session = requests.Session()

        try:
            for i in range(depth):
                if not to_visit:
                    break
                
                current_urls_to_visit = list(to_visit)
                to_visit.clear()

                for current_url in current_urls_to_visit:
                    if current_url in visited:
                        continue
                    
                    yield yield_event({"status": f"Crawling (Depth {i+1}): {current_url}"})
                    visited.add(current_url)

                    try:
                        driver.get(current_url)
                        
                        # --- NEW: Smarter wait condition ---
                        # Wait for an element that is *not* part of the challenge page.
                        # For thevespiary.org, this is id="app". We'll use a more generic
                        # wait for any element with an ID, which is *usually* the main content.
                        # Increased timeout to 20s for slow challenges.
                        try:
                            WebDriverWait(driver, 20).until(
                                EC.presence_of_element_located((By.CSS_SELECTOR, "#app, #main, #root, .main, .app, .container"))
                            )
                            yield yield_event({"status": "Bot challenge likely passed. Scraping..."})
                        except TimeoutException:
                            yield yield_event({"status": "Timeout waiting for main content. Scraping whatever is present..."})
                            # Proceed anyway, it might be a simple page
                        # --- End smarter wait ---

                        
                        # --- Improved dynamic content scroll ---
                        last_height = driver.execute_script("return document.body.scrollHeight")
                        scroll_pause_time = 1.5 # Time to wait after each scroll
                        
                        for _ in range(5): # Max 5 scrolls to prevent infinite loops
                            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                            time.sleep(scroll_pause_time) 
                            new_height = driver.execute_script("return document.body.scrollHeight")
                            if new_height == last_height:
                                break 
                            last_height = new_height
                        # --- End of improved scroll ---

                        soup = BeautifulSoup(driver.page_source, 'html.parser')
                        
                        for a in soup.find_all('a', href=True):
                            href = a['href']
                            if href and not href.startswith(('mailto:', 'tel:')):
                                full_url = urljoin(current_url, href)
                                
                                if follow_external or (get_domain_name(full_url) == base_domain):
                                    if full_url not in all_links:
                                        all_links.add(full_url)
                                        yield yield_event({"link": full_url})
                                    if full_url not in visited:
                                        to_visit.add(full_url)
                        
                        # Pass the 'soup' object you already have
                        js_links = find_links_in_js(session, soup, current_url, base_domain, follow_external)
                        for link in js_links:
                            if link not in all_links:
                                all_links.add(link)
                                yield yield_event({"link": link})
                            if link not in visited:
                                to_visit.add(link)

                    except TimeoutException:
                        print(f"Timed out on {current_url}")
                    except Exception as e:
                        print(f"Error crawling {current_url}: {e}")
        finally:
            driver.quit()
        
        yield "event: end\ndata: Scan finished\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@app.route('/find-subdomains', methods=['POST'])
def find_subdomains_endpoint():
    data = request.get_json()
    domain = data.get('domain')
    brute_force = data.get('brute_force', False)
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    results = find_subdomains_internal(domain, brute_force)
    
    try:
        with open(LAST_RESULTS_FILE, 'w') as f:
            json.dump({'domain': domain, 'subdomains': results}, f, indent=4)
        print(f"Saved last search results for {domain}.")
    except Exception as e:
        print(f"Error saving last results: {e}")
        
    return jsonify({"subdomains": results})


@app.route('/archive-url', methods=['GET'])
def archive_url():
    url_to_archive = request.args.get('url')
    if not url_to_archive:
        def error_gen():
            yield f"data: {json.dumps({'error': 'URL is required'})}\n\n"
            yield "event: end\n\n"
        return Response(stream_with_context(error_gen()), mimetype='text/event-stream')

    archive_api_url = f"https://web.archive.org/save/{url_to_archive}"
    headers = {'User-Agent': 'Ariadne Scanner/1.3'}

    def generate():
        def yield_event(data):
            return f"data: {json.dumps(data)}\n\n"

        if not PROXIES_ENABLED or not PROXY_LIST:
            yield yield_event({"status": "No proxy enabled. Connecting directly..."})
            try:
                http_manager = urllib3.PoolManager(headers=headers, cert_reqs='CERT_NONE', retries=Retry(total=3, backoff_factor=1))
                response = http_manager.request('GET', archive_api_url, timeout=30.0)
                if response.status >= 400:
                    raise urllib3.exceptions.HTTPError(f"Archive.org returned status {response.status}")
                yield yield_event({"success": "Successfully submitted to Internet Archive."})
            except Exception as e:
                error_message = f"Failed to contact Internet Archive: {e}"
                print(f"Error contacting Internet Archive directly: {e}")
                yield yield_event({"error": error_message})
            finally:
                yield "event: end\n\n"
            return

        num_proxies = len(PROXY_LIST)
        for i in range(num_proxies):
            proxy_line = next(PROXY_CYCLE).strip()
            if not proxy_line:
                continue
            
            if not re.match(r'^(http|https|socks4|socks5)://', proxy_line):
                proxy_line = 'socks5://' + proxy_line
            
            yield yield_event({"status": f"Trying proxy ({i+1}/{num_proxies})..."})
            print(f"Attempting to use proxy: {proxy_line}")
            
            try:
                proxy_scheme = urlparse(proxy_line).scheme
                
                if proxy_scheme in ('socks4', 'socks5'):
                    if SOCKSProxyManager is None:
                        raise ImportError("SOCKSProxyManager not available. 'pysocks' might be missing.")
                    http_manager = SOCKSProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
                elif proxy_scheme in ('http', 'https'):
                    http_manager = urllib3.ProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
                else:
                    raise ValueError(f"Unsupported proxy scheme: {proxy_scheme}")

                response = http_manager.request('GET', archive_api_url, timeout=20.0)

                if response.status < 400:
                    print(f"Proxy {proxy_line} successful!")
                    yield yield_event({"success": "Successfully submitted to Internet Archive."})
                    yield "event: end\n\n"
                    return
                else:
                    status_message = f"Proxy failed with status {response.status}. Trying next..."
                    print(status_message)
                    yield yield_event({"status": status_message})
            except urllib3.exceptions.ProxyError as e:
                print(f"Proxy {proxy_line} failed: {e}. Trying next...")
                yield yield_event({"status": "Proxy connection failed. Trying next..."})
                continue
            except Exception as e:
                print(f"Proxy {proxy_line} encountered a general error: {e}. Trying next...")
                yield yield_event({"status": "Proxy error. Trying next..."})
                continue
        final_error_message = "All available proxies failed to connect."
        print(final_error_message)
        yield yield_event({"error": final_error_message})
        yield "event: end\n\n"
    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@app.route('/check-diff', methods=['POST'])
def check_diff():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # For diffs, we need to use Selenium to get live content if it's protected
    driver = None
    try:
        full_url = normalize_url_for_requests(url)
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={full_url}&output=json&fl=timestamp&statuscode=200&limit=-1"
        cdx_response = requests.get(cdx_url)
        cdx_response.raise_for_status()
        snapshots = cdx_response.json()
        if len(snapshots) <= 1:
            return jsonify({"has_changes": False, "message": "Not previously archived or no successful captures found."})
        
        latest_timestamp = snapshots[-1][0]
        try:
            date_obj = datetime.strptime(latest_timestamp, '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
            formatted_date = date_obj.astimezone().strftime('%B %d, %Y at %I:%M %p %Z')
        except ValueError:
            formatted_date = latest_timestamp

        archived_url = f"https://web.archive.org/web/{latest_timestamp}id_/{full_url}"
        archived_response = requests.get(archived_url, timeout=20)
        archived_response.raise_for_status()
        archived_soup = BeautifulSoup(archived_response.text, 'html.parser')
        archived_text = archived_soup.get_text()
        
        # --- NEW: Use Selenium for live text ---
        print("Diff check: using Selenium for live content.")
        driver = get_chrome_driver(domain_for_cookie=get_domain_name(full_url))
        if not driver:
            raise Exception("Could not initialize WebDriver for diff check.")
        
        driver.get(full_url)
        try:
            # Wait for the main content to appear, similar to scan_site
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#app, #main, #root, .main, .app, .container"))
            )
        except TimeoutException:
            print("Diff check: Timeout waiting for main content. Using whatever loaded.")
            
        live_soup = BeautifulSoup(driver.page_source, 'html.parser')
        live_text = live_soup.get_text()
        # --- End Selenium use ---
        
        diff = difflib.HtmlDiff(wrapcolumn=80).make_table(
            archived_text.splitlines(),
            live_text.splitlines(),
            fromdesc=f"Archived on {formatted_date}",
            todesc="Live Version"
        )

        if archived_text == live_text:
             return jsonify({"has_changes": False, "message": f"No significant changes detected since the last archive on {formatted_date}."})
        else:
             return jsonify({"has_changes": True, "diff_html": diff})
    except requests.RequestException as e:
        return jsonify({"error": f"Network error during diff check: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    finally:
        if driver:
            driver.quit()


@app.route('/get-schedules', methods=['GET'])
def get_schedules():
    """Returns a list of all currently scheduled jobs."""
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "domain": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else 'Paused',
            "interval": str(job.trigger)
        })
    return jsonify(jobs)

@app.route('/get-local-archives', methods=['GET'])
def get_local_archives():
    """Lists all locally archived files, scanning subdirectories."""
    try:
        archived_files = []
        for root, dirs, files in os.walk(LOCAL_ARCHIVES_DIR):
            for file in files:
                if file.endswith('.html'):
                    relative_path = os.path.relpath(os.path.join(root, file), LOCAL_ARCHIVES_DIR)
                    archived_files.append(relative_path.replace("\\", "/")) 
        return jsonify(sorted(archived_files, reverse=True))
    except FileNotFoundError:
        return jsonify([])
    except Exception as e:
        print(f"Error listing local archives: {e}")
        return jsonify({"error": "Could not retrieve archive list."}), 500

@app.route('/local_archives/<path:filename>')
def serve_local_archive(filename):
    """Serves a specific locally archived HTML file."""
    return send_from_directory(LOCAL_ARCHIVES_DIR, filename)

@app.route('/get-last-results', methods=['GET'])
def get_last_results():
    try:
        with open(LAST_RESULTS_FILE, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})

@app.route('/schedule-scan', methods=['POST'])
def schedule_scan():
    """Schedules a new recurring scan."""
    data = request.get_json()
    domain = data.get('domain')
    start_date_str = data.get('start_date')
    frequency = data.get('frequency')
    
    if not all([domain, start_date_str, frequency]):
        return jsonify({"error": "Domain, start date, and frequency are required."}), 400

    try:
        start_date = datetime.fromisoformat(start_date_str)
        trigger_args = {}
        if frequency == 'daily': trigger_args['days'] = 1
        elif frequency == 'weekly': trigger_args['weeks'] = 1
        elif frequency == 'bi-weekly': trigger_args['weeks'] = 2
        elif frequency == 'monthly': trigger_args['weeks'] = 4 
        elif frequency == 'every-other-month': trigger_args['weeks'] = 8 

        job = scheduler.add_job(
            run_scheduled_scan,
            args=[domain],
            trigger=IntervalTrigger(**trigger_args),
            name=domain,
            next_run_time=start_date
        )
        
        schedules = []
        try:
            with open(SCHEDULES_FILE, 'r') as f:
                schedules = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        schedules.append({
            "id": job.id, "domain": domain, "next_run_time": job.next_run_time.isoformat(),
            "weeks": trigger_args.get('weeks'), "days": trigger_args.get('days')
        })
        with open(SCHEDULES_FILE, 'w') as f:
            json.dump(schedules, f, indent=4)

        return jsonify({"message": "Scan scheduled successfully!", "job_id": job.id})
    except Exception as e:
        return jsonify({"error": f"Failed to schedule scan: {e}"}), 500

@app.route('/delete-schedule', methods=['POST'])
def delete_schedule():
    """Deletes a scheduled job."""
    data = request.get_json()
    job_id = data.get('id')
    if not job_id:
        return jsonify({"error": "Job ID is required."}), 400

    try:
        scheduler.remove_job(job_id)
        schedules = []
        try:
            with open(SCHEDULES_FILE, 'r') as f:
                schedules = json.load(f)
            schedules = [s for s in schedules if s['id'] != job_id]
            with open(SCHEDULES_FILE, 'w') as f:
                json.dump(schedules, f, indent=4)
        except (FileNotFoundError, json.JSONDecodeError):
            pass 
        return jsonify({"message": "Schedule deleted successfully."})
    except Exception as e:
        return jsonify({"error": f"Failed to delete schedule: {e}"}), 500

@app.route('/save-local-copy', methods=['GET'])
def save_local_copy():
    url = request.args.get('url')
    folder_name = request.args.get('folder', '')

    if not url:
        return Response(stream_with_context('data: {"error": "URL is required"}\n\n'), mimetype='text/event-stream')

    def generate():
        def yield_event(data):
            return f"data: {json.dumps(data)}\n\n"

        driver = None
        try:
            yield yield_event({"status": "Loading page in browser..."})
            driver = get_chrome_driver(domain_for_cookie=get_domain_name(url))
            if not driver:
                yield yield_event({"error": "Could not initialize web driver."})
                return

            driver.get(url)
            
            # --- Smarter wait + dynamic content scroll ---
            try:
                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "#app, #main, #root, .main, .app, .container"))
                )
                yield yield_event({"status": "Main content loaded. Scrolling..."})
            except TimeoutException:
                yield yield_event({"status": "Timeout waiting for main content. Scrolling..."})

            last_height = driver.execute_script("return document.body.scrollHeight")
            scroll_pause_time = 1.5 
            
            for _ in range(5): # Max 5 scrolls
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(scroll_pause_time) 
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break 
                last_height = new_height
            # --- End of scroll ---
            
            page_source = driver.page_source
            soup = BeautifulSoup(page_source, 'html.parser')

            def fetch_and_embed(tag, attr):
                try:
                    asset_url = tag.get(attr)
                    if not asset_url or asset_url.startswith('data:'):
                        return
                    
                    full_asset_url = urljoin(url, asset_url)
                    # Use selenium's session if possible? No, stick to requests
                    response = requests.get(full_asset_url, timeout=10, verify=False)
                    if response.status_code == 200:
                        mime_type, _ = mimetypes.guess_type(full_asset_url)
                        if not mime_type:
                            mime_type = response.headers.get('Content-Type', 'application/octet-stream')
                        
                        encoded_content = base64.b64encode(response.content).decode('utf-8')
                        tag[attr] = f"data:{mime_type};base64,{encoded_content}"
                except Exception as e:
                    print(f"Could not embed asset {asset_url}: {e}")

            yield yield_event({"status": "Embedding CSS..."})
            for link in soup.find_all('link', rel='stylesheet'):
                fetch_and_embed(link, 'href')

            yield yield_event({"status": "Embedding Images..."})
            for img in soup.find_all('img'):
                fetch_and_embed(img, 'src')
                if img.get('srcset'):
                    del img['srcset'] 

            yield yield_event({"status": "Embedding Scripts..."})
            for script in soup.find_all('script'):
                if script.get('src'):
                    fetch_and_embed(script, 'src')
            
            yield yield_event({"status": "Saving file..."})
            
            domain = urlparse(url).hostname or 'unknown'
            path = urlparse(url).path.replace('/', '_') or 'index'
            filename = f"{domain}{path}.html"
            filename = re.sub(r'[^\w\.-]', '_', filename) 
            
            sane_folder = secure_filename(folder_name)
            target_dir = os.path.join(LOCAL_ARCHIVES_DIR, sane_folder) if sane_folder else LOCAL_ARCHIVES_DIR
            
            os.makedirs(target_dir, exist_ok=True)
            
            save_path = os.path.join(target_dir, filename)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(str(soup))
            
            relative_path = os.path.relpath(save_path, LOCAL_ARCHIVES_DIR).replace("\\", "/")
            yield yield_event({"success": f"Saved as {relative_path}"})

        except Exception as e:
            print(f"Error saving local copy for {url}: {e}")
            yield yield_event({"error": f"Failed to save local copy: {e}"})
        finally:
            if driver:
                driver.quit()
            yield "event: end\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


# --- Proxy Test Function ---
def test_proxy(proxy_line):
    """Tests a single proxy line against a neutral target."""
    if not proxy_line:
        return None
    
    if not re.match(r'^(http|https|socks4|socks5)://', proxy_line):
        proxy_line = 'socks5://' + proxy_line
    
    headers = {'User-Agent': 'Ariadne Proxy Tester/1.0'}
    test_url = "https://httpbin.org/ip" 
    
    try:
        proxy_scheme = urlparse(proxy_line).scheme
        
        if proxy_scheme in ('socks4', 'socks5'):
            if SOCKSProxyManager is None:
                raise ImportError("SOCKSProxyManager not available.")
            http_manager = SOCKSProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
        elif proxy_scheme in ('http', 'https'):
            http_manager = urllib3.ProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
        else:
            raise ValueError(f"Unsupported scheme: {proxy_scheme}")

        response = http_manager.request('GET', test_url, timeout=10.0)
        
        if response.status == 200:
            try:
                data = json.loads(response.data.decode('utf-8'))
                ip = data.get('origin', 'Unknown IP')
                return {"proxy": proxy_line, "status": "Working", "ip": ip}
            except Exception:
                return {"proxy": proxy_line, "status": "Working", "ip": "Response OK, IP unparsed"}
        else:
            return {"proxy": proxy_line, "status": f"Failed (Status: {response.status})", "ip": "N/A"}
            
    except Exception as e:
        return {"proxy": proxy_line, "status": f"Failed ({type(e).__name__})", "ip": "N/A"}


@app.route('/test-proxies', methods=['POST'])
def test_proxies_endpoint():
    data = request.get_json()
    proxies = data.get('proxies', [])
    if not proxies or not isinstance(proxies, list):
        return jsonify({"error": "A list of proxies is required"}), 400
    
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_proxy = {executor.submit(test_proxy, proxy): proxy for proxy in proxies if proxy.strip()}
        for future in as_completed(future_to_proxy):
            result = future.result()
            if result:
                results.append(result)
                
    return jsonify({"results": results})


# --- Other Endpoints (get_ip, get_registrar, etc.) ---
@app.route('/get-ip', methods=['POST'])
def get_ip_address():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    try:
        answers = my_resolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        return jsonify({"ip_address": ip_address})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        print(f"Error resolving IP for {domain}: {e}")
        return jsonify({"ip_address": "Not found"})
    except Exception as e:
        print(f"Error resolving IP for {domain}: {e}")
        return jsonify({"error": "An error occurred during IP lookup."}), 500
@app.route('/get-registrar', methods=['POST'])
def get_registrar():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    try:
        domain_info = whois.whois(domain)
        registrar = domain_info.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        return jsonify({"registrar": registrar or "Not found"})
    except Exception as e:
        print(f"Error during WHOIS lookup for {domain}: {e}")
        return jsonify({"registrar": "Error or not found"})
@app.route('/get-settings', methods=['GET'])
def get_settings():
    try:
        with open('proxies.txt', 'r') as f:
            proxies_content = f.read()
    except FileNotFoundError:
        proxies_content = "# Add proxy addresses here, one per line (e.g., http://user:pass@host:port).\n"
    
    return jsonify({
        "proxies": proxies_content, 
        "enabled": PROXIES_ENABLED,
        "archive_folder": ARCHIVE_FOLDER,
        "cookie_domain": AUTH_COOKIE.get('domain', '') if AUTH_COOKIE else '',
        "cookie_name": AUTH_COOKIE.get('name', '') if AUTH_COOKIE else '',
        "cookie_value": AUTH_COOKIE.get('value', '') if AUTH_COOKIE else ''
    })

@app.route('/update-settings', methods=['POST'])
def update_settings():
    global PROXIES_ENABLED, ARCHIVE_FOLDER, AUTH_COOKIE
    data = request.get_json()
    proxies_content = data.get('proxies', '')
    proxies_enabled_state = data.get('enabled', True)
    archive_folder_name = data.get('archive_folder', '')
    
    # NEW: Get cookie data
    cookie_domain = data.get('cookie_domain', '').strip()
    cookie_name = data.get('cookie_name', '').strip()
    cookie_value = data.get('cookie_value', '').strip()

    try:
        with open('proxies.txt', 'w') as f:
            f.write(proxies_content)
        load_proxies()
        
        PROXIES_ENABLED = proxies_enabled_state
        ARCHIVE_FOLDER = archive_folder_name
        
        # NEW: Update global auth cookie
        if cookie_domain and cookie_name and cookie_value:
            AUTH_COOKIE = {
                'name': cookie_name,
                'value': cookie_value,
                'domain': cookie_domain if cookie_domain.startswith('.') else f".{cookie_domain}"
            }
            print(f"Updated auth cookie for domain: {AUTH_COOKIE['domain']}")
        else:
            AUTH_COOKIE = None
            print("Auth cookie cleared.")

        save_settings()
        return jsonify({"message": "Settings saved successfully."})
    except Exception as e:
        print(f"Error saving settings: {e}")
        return jsonify({"error": "Failed to save settings on the server."}), 500
@app.route('/analyze-headers', methods=['POST'])
def analyze_headers_endpoint():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    headers_to_check = {
        'Content-Security-Policy': 'Missing', 'Strict-Transport-Security': 'Missing',
        'X-Content-Type-Options': 'Missing', 'X-Frame-Options': 'Missing',
        'Referrer-Policy': 'Missing', 'Permissions-Policy': 'Missing'
    }
    try:
        full_url = normalize_url_for_requests(url)
        # Use a session with a browser-like user agent
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        response = session.get(full_url, timeout=10, allow_redirects=True, verify=False)
        
        # Handle cases where we get the challenge page
        if "Checking if the site connection is secure" in response.text:
            return jsonify({"error": "Could not analyze headers: Site is protected by an anti-bot service."}), 503

        for header in headers_to_check:
            if header in response.headers:
                headers_to_check[header] = 'Present'
        return jsonify({"headers": headers_to_check})
    except requests.RequestException as e:
        print(f"Error fetching headers for {url}: {e}")
        return jsonify({"error": f"Could not fetch headers from the URL."}), 500
@app.route('/detect-tech', methods=['POST'])
def detect_tech_endpoint():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    detected_tech = set()
    try:
        full_url = normalize_url_for_requests(url)
        # Use a session with a browser-like user agent
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        response = session.get(full_url, timeout=10, allow_redirects=True, verify=False)
        
        if "Checking if the site connection is secure" in response.text:
            return jsonify({"error": "Could not detect tech: Site is protected by an anti-bot service."}), 503

        content = response.text
        headers = response.headers
        soup = BeautifulSoup(content, 'html.parser')
        if 'wp-content' in content or 'wp-includes' in content: detected_tech.add('WordPress')
        if soup.select_one('#react-root') or 'react.js' in content or 'react.min.js' in content: detected_tech.add('React')
        if soup.select_one('[ng-version]'): detected_tech.add('Angular')
        if soup.select_one('#app') and ('vue.js' in content or 'vue.min.js' in content): detected_tech.add('Vue.js')
        if 'jquery' in content: detected_tech.add('jQuery')
        if 'bootstrap' in content: detected_tech.add('Bootstrap')
        if 'X-Powered-By' in headers and 'ASP.NET' in headers['X-Powered-By']: detected_tech.add('ASP.NET')
        if 'cloudflare' in headers.get('Server', ''): detected_tech.add('Cloudflare')
        return jsonify({"technologies": list(detected_tech)})
    except requests.RequestException as e:
        print(f"Error fetching page for tech detection {url}: {e}")
        return jsonify({"error": f"Could not fetch page content."}), 500
@app.route('/check-links', methods=['POST'])
def check_links_endpoint():
    data = request.get_json()
    urls = data.get('urls')
    if not urls or not isinstance(urls, list):
        return jsonify({"error": "A list of URLs is required"}), 400
    results = {}
    session = requests.Session()
    # Use a browser-like user agent
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
    
    def check_url(url):
        try:
            response = session.head(url, timeout=5, allow_redirects=True, verify=False)
            return url, response.status_code
        except requests.RequestException:
            try:
                # Fallback to GET if HEAD fails
                response = session.get(url, timeout=5, allow_redirects=True, verify=False)
                return url, response.status_code
            except requests.RequestException:
                return url, "Error"
                
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(check_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            url, status = future.result()
            results[url] = status
            
    return jsonify({"link_statuses": results})


if __name__ == '__main__':
    print("Starting Ariadne backend...") # Added a startup message
    os.makedirs(LOCAL_ARCHIVES_DIR, exist_ok=True)
    load_settings() # Load settings first to get cookie info
    load_proxies()
    scheduler.start()
    load_schedules()
    # Ensure the scheduler shuts down cleanly when the app exits
    atexit.register(lambda: scheduler.shutdown())
    app.run(port=5010, debug=False, threaded=True) # Debug mode should be off for scheduler

