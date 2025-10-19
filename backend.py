import re
import requests
import socket
import time
from flask import Flask, jsonify, request, Response, stream_with_context
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
from datetime import datetime
import atexit

# Suppress only the single InsecureRequestWarning from urllib3 needed for this specific app
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__, static_url_path='', static_folder='.')
CORS(app)

# --- Global variables & Configuration ---
PROXY_LIST = []
PROXY_CYCLE = None
PROXIES_ENABLED = True
SETTINGS_FILE = 'settings.json'
SCHEDULES_FILE = 'schedules.json'

# --- Scheduler Setup ---
scheduler = BackgroundScheduler()

def load_settings():
    """Loads settings from the settings file."""
    global PROXIES_ENABLED
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
            PROXIES_ENABLED = settings.get('proxies_enabled', True)
        print(f"Settings loaded: Proxies enabled -> {PROXIES_ENABLED}")
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"{SETTINGS_FILE} not found or invalid. Creating with default settings.")
        PROXIES_ENABLED = True
        save_settings()

def save_settings():
    """Saves the current settings to the settings file."""
    with open(SETTINGS_FILE, 'w') as f:
        json.dump({'proxies_enabled': PROXIES_ENABLED}, f, indent=4)
    print(f"Settings saved: Proxies enabled -> {PROXIES_ENABLED}")


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

def find_subdomains_internal(domain):
    found_subdomains = set()
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15, verify=False)
        if response.ok:
            for cert in response.json():
                name_value = cert.get('name_value')
                if name_value:
                    subdomains = name_value.split('\n')
                    for sub in subdomains:
                        if sub.endswith(f".{domain}") and '*' not in sub and sub != domain:
                            found_subdomains.add(sub)
    except Exception as e:
        print(f"Scheduled scan: Error querying crt.sh for {domain}: {e}")
    return sorted(list(found_subdomains))

def check_diff_internal(url):
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp&statuscode=200&limit=-1"
        cdx_response = requests.get(cdx_url, timeout=20)
        cdx_response.raise_for_status()
        snapshots = cdx_response.json()

        if len(snapshots) <= 1:
            return True # Not archived before, so it's a "change"

        latest_timestamp = snapshots[-1][0]
        archived_url = f"https://web.archive.org/web/{latest_timestamp}id_/{url}"
        
        archived_response = requests.get(archived_url, timeout=20)
        archived_soup = BeautifulSoup(archived_response.text, 'html.parser')
        archived_text = archived_soup.get_text()

        live_response = requests.get(url, timeout=20, verify=False)
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
            proxy_line = 'http://' + proxy_line
        try:
            http_manager = urllib3.ProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE')
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
    subdomains = find_subdomains_internal(domain)
    if not subdomains:
        print(f"No subdomains found for {domain}. Scan complete.")
        return

    print(f"Found {len(subdomains)} subdomains. Checking each for changes...")
    for subdomain in subdomains:
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
        return domain
    except Exception as e:
        print(f"Error parsing domain from URL '{url}': {e}")
        return None

def get_chrome_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    try:
        service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=chrome_options)
    except (WebDriverException, ValueError) as e:
        print(f"Could not start WebDriver via manager: {e}. Falling back to default PATH if possible.")
        try:
            return webdriver.Chrome(options=chrome_options)
        except WebDriverException as e_fallback:
            print(f"Fallback WebDriver initialization failed: {e_fallback}")
            return None

def find_links_in_js(session, base_url, domain, follow_external):
    js_links = set()
    try:
        response = session.get(base_url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
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
                    trigger=IntervalTrigger(weeks=job_info.get('weeks', 0), days=job_info.get('days', 0)),
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
        
        yield yield_event({"status": "Checking for sitemap..."})
        try:
            robots_url = urljoin(url, '/robots.txt')
            sitemap_urls = []
            try:
                r = requests.get(robots_url, timeout=5, verify=False)
                if r.ok:
                    for line in r.text.splitlines():
                        if line.lower().startswith('sitemap:'):
                            sitemap_urls.append(line.split(':', 1)[1].strip())
            except requests.RequestException:
                pass 
            
            if not sitemap_urls:
                sitemap_urls.append(urljoin(url, '/sitemap.xml'))

            for sitemap_url in sitemap_urls:
                try:
                    r = requests.get(sitemap_url, timeout=5, verify=False)
                    if r.ok:
                        yield yield_event({"status": f"Parsing sitemap: {sitemap_url}"})
                        tree = ET.fromstring(r.content)
                        for elem in tree.iterfind('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                            link = elem.text.strip()
                            if link and (follow_external or get_domain_name(link) == base_domain):
                                all_links.add(link)
                                yield yield_event({"link": link})
                except Exception:
                    pass
        except Exception as e:
            print(f"Error during sitemap check: {e}")

        yield yield_event({"status": "Starting browser crawl..."})
        driver = get_chrome_driver()
        if not driver:
            yield yield_event({"error": "Could not initialize web driver."})
            yield "event: end\ndata: Scan finished\n\n"
            return
        
        to_visit = {url}
        visited = set()
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
                        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                        
                        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                        time.sleep(2)

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
                        
                        js_links = find_links_in_js(session, current_url, base_domain, follow_external)
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
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
        
    found_subdomains = set()

    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15, verify=False)
        if response.ok:
            for cert in response.json():
                name_value = cert.get('name_value')
                if name_value:
                    subdomains = name_value.split('\n')
                    for sub in subdomains:
                        if sub.endswith(f".{domain}") and '*' not in sub and sub != domain:
                            found_subdomains.add((sub, 'CT'))
    except Exception as e:
        print(f"Error querying crt.sh: {e}")

    for record_type in ['MX', 'NS', 'CNAME']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                hostname = rdata.target.to_text().rstrip('.') if record_type != 'MX' else rdata.exchange.to_text().rstrip('.')
                if hostname.endswith(domain) and hostname != domain:
                    found_subdomains.add((hostname, record_type))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as e:
            print(f"Error querying {record_type} records for {domain}: {e}")

    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = rdata.to_text()
            try:
                rev_name = dns.reversename.from_address(ip)
                rev_answers = dns.resolver.resolve(rev_name, "PTR")
                for rev_rdata in rev_answers:
                    hostname = rev_rdata.to_text().rstrip('.')
                    if hostname.endswith(domain) and hostname != domain:
                         found_subdomains.add((hostname, 'PTR'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            except Exception as e:
                print(f"Reverse DNS lookup error for {ip}: {e}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
         pass
    except Exception as e:
        print(f"Error during initial A record lookup for {domain}: {e}")
    
    results = [{"name": name, "type": type} for name, type in sorted(list(found_subdomains))]
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
                proxy_line = 'http://' + proxy_line
            yield yield_event({"status": f"Trying proxy ({i+1}/{num_proxies})..."})
            print(f"Attempting to use proxy: {proxy_line}")
            try:
                http_manager = urllib3.ProxyManager(proxy_line, headers=headers, cert_reqs='CERT_NONE', retries=False)
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
                yield yield_event({"status": "Proxy timeout. Trying next..."})
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
    try:
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp&statuscode=200&limit=-1"
        cdx_response = requests.get(cdx_url)
        cdx_response.raise_for_status()
        snapshots = cdx_response.json()
        if len(snapshots) <= 1:
            return jsonify({"has_changes": False, "message": "Not previously archived or no successful captures found."})
        latest_timestamp = snapshots[-1][0]
        archived_url = f"https://web.archive.org/web/{latest_timestamp}id_/{url}"
        archived_response = requests.get(archived_url, timeout=20)
        archived_response.raise_for_status()
        archived_soup = BeautifulSoup(archived_response.text, 'html.parser')
        archived_text = archived_soup.get_text()
        live_response = requests.get(url, timeout=20, verify=False)
        live_response.raise_for_status()
        live_soup = BeautifulSoup(live_response.text, 'html.parser')
        live_text = live_soup.get_text()
        diff = difflib.HtmlDiff(wrapcolumn=80).make_table(
            archived_text.splitlines(),
            live_text.splitlines(),
            fromdesc=f"Archived on {latest_timestamp}",
            todesc="Live Version"
        )
        if archived_text == live_text:
             return jsonify({"has_changes": False, "message": "No significant changes detected since the last archive."})
        else:
             return jsonify({"has_changes": True, "diff_html": diff})
    except requests.RequestException as e:
        return jsonify({"error": f"Network error during diff check: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


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
        if frequency == 'weekly': trigger_args['weeks'] = 1
        elif frequency == 'bi-weekly': trigger_args['weeks'] = 2
        elif frequency == 'monthly': trigger_args['weeks'] = 4 # Approx
        elif frequency == 'every-other-month': trigger_args['weeks'] = 8 # Approx

        job = scheduler.add_job(
            run_scheduled_scan,
            args=[domain],
            trigger=IntervalTrigger(**trigger_args),
            name=domain,
            next_run_time=start_date
        )
        
        # Save schedule to file for persistence
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
        # Update the schedules file
        schedules = []
        try:
            with open(SCHEDULES_FILE, 'r') as f:
                schedules = json.load(f)
            schedules = [s for s in schedules if s['id'] != job_id]
            with open(SCHEDULES_FILE, 'w') as f:
                json.dump(schedules, f, indent=4)
        except (FileNotFoundError, json.JSONDecodeError):
            pass # File might already be empty or gone
        return jsonify({"message": "Schedule deleted successfully."})
    except Exception as e:
        return jsonify({"error": f"Failed to delete schedule: {e}"}), 500

# --- Other Endpoints (get_ip, get_registrar, etc.) ---
@app.route('/get-ip', methods=['POST'])
def get_ip_address():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        return jsonify({"ip_address": ip_address})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
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
@app.route('/get-proxy-settings', methods=['GET'])
def get_proxy_settings():
    try:
        with open('proxies.txt', 'r') as f:
            proxies_content = f.read()
    except FileNotFoundError:
        proxies_content = "# Add proxy addresses here, one per line (e.g., http://user:pass@host:port).\n"
    return jsonify({"proxies": proxies_content, "enabled": PROXIES_ENABLED})
@app.route('/update-proxy-settings', methods=['POST'])
def update_proxy_settings():
    global PROXIES_ENABLED
    data = request.get_json()
    proxies_content = data.get('proxies', '')
    proxies_enabled_state = data.get('enabled', True)
    try:
        with open('proxies.txt', 'w') as f:
            f.write(proxies_content)
        load_proxies()
        PROXIES_ENABLED = proxies_enabled_state
        save_settings()
        return jsonify({"message": "Proxy settings saved successfully."})
    except Exception as e:
        print(f"Error saving proxy settings: {e}")
        return jsonify({"error": "Failed to save proxy settings on the server."}), 500
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
        response = requests.get(full_url, timeout=10, allow_redirects=True, verify=False)
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
        response = requests.get(full_url, timeout=10, allow_redirects=True, verify=False)
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
    def check_url(url):
        try:
            response = session.head(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Ariadne Scanner/1.2'}, verify=False)
            return url, response.status_code
        except requests.RequestException:
            return url, "Error"
    for url in urls:
        _, status = check_url(url)
        results[url] = status
    return jsonify({"link_statuses": results})


if __name__ == '__main__':
    load_settings()
    load_proxies()
    scheduler.start()
    load_schedules()
    # Ensure the scheduler shuts down cleanly when the app exits
    atexit.register(lambda: scheduler.shutdown())
    app.run(port=5010, debug=False, threaded=True) # Debug mode should be off for scheduler

