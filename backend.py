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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__, static_url_path='', static_folder='.')
CORS(app)

# Global variable to hold the proxy list and a cycle iterator
PROXY_LIST = []
PROXY_CYCLE = None

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
        response = session.get(base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script', src=True):
            script_url = urljoin(base_url, script['src'])
            if follow_external or get_domain_name(script_url) == domain:
                try:
                    js_content = session.get(script_url, timeout=5).text
                    paths = re.findall(r'[\'"](/[\w\d/.-]+)[\'"]', js_content)
                    for path in paths:
                        js_links.add(urljoin(base_url, path))
                except requests.RequestException as e:
                    print(f"Could not fetch JS file {script_url}: {e}")
    except requests.RequestException as e:
        print(f"Could not fetch base URL for JS scan {base_url}: {e}")
    return js_links

@app.route('/')
def serve_frontend():
    return app.send_static_file('index.html')

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
                r = requests.get(robots_url, timeout=5)
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
                    r = requests.get(sitemap_url, timeout=5)
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
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
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


@app.route('/archive-url', methods=['POST'])
def archive_url():
    data = request.get_json()
    url_to_archive = data.get('url')
    if not url_to_archive:
        return jsonify({"error": "URL is required"}), 400

    try:
        archive_api_url = f"https://web.archive.org/save/{url_to_archive}"
        
        proxies = None
        if PROXY_CYCLE:
            proxy = next(PROXY_CYCLE)
            proxies = {"http": proxy, "https": proxy}

        session = requests.Session()
        retry_strategy = Retry(
            total=3,  
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        response = session.get(
            archive_api_url, 
            timeout=30, 
            headers={'User-Agent': 'SiteScanner/1.0'}, 
            verify=False,
            proxies=proxies
        )
        
        response.raise_for_status() 
        
        return jsonify({"message": "Successfully submitted to Internet Archive."})

    except requests.exceptions.RequestException as e:
        error_message = "An unknown network error occurred."
        if hasattr(e, 'response') and e.response is not None:
            status_code = e.response.status_code
            if status_code == 429:
                error_message = "Rate limited. Try again later."
            elif status_code >= 500:
                error_message = f"Archive.org server error ({status_code})."
            else:
                error_message = f"Archive.org returned status {status_code}."
        elif "Max retries exceeded" in str(e):
            error_message = "Connection failed after retries."
        
        print(f"Error contacting Internet Archive after retries: {e}")
        return jsonify({"error": error_message}), 504


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

@app.route('/get-proxies', methods=['GET'])
def get_proxies():
    try:
        with open('proxies.txt', 'r') as f:
            proxies_content = f.read()
        return jsonify({"proxies": proxies_content})
    except FileNotFoundError:
        return jsonify({"proxies": "# Add proxy addresses here, one per line."})

@app.route('/update-proxies', methods=['POST'])
def update_proxies():
    data = request.get_json()
    proxies_content = data.get('proxies', '')
    try:
        with open('proxies.txt', 'w') as f:
            f.write(proxies_content)
        load_proxies() # Reload proxies into memory
        return jsonify({"message": "Proxy list saved successfully."})
    except Exception as e:
        print(f"Error saving proxies.txt: {e}")
        return jsonify({"error": "Failed to save proxy list on the server."}), 500


def normalize_url_for_requests(url):
    if not re.match(r'^[a-zA-Z]+://', url):
        return 'https://' + url
    return url

@app.route('/analyze-headers', methods=['POST'])
def analyze_headers_endpoint():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    headers_to_check = {
        'Content-Security-Policy': 'Missing',
        'Strict-Transport-Security': 'Missing',
        'X-Content-Type-Options': 'Missing',
        'X-Frame-Options': 'Missing',
        'Referrer-Policy': 'Missing',
        'Permissions-Policy': 'Missing'
    }
    
    try:
        full_url = normalize_url_for_requests(url)
        response = requests.get(full_url, timeout=10, allow_redirects=True)
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
        response = requests.get(full_url, timeout=10, allow_redirects=True)
        content = response.text
        headers = response.headers
        soup = BeautifulSoup(content, 'html.parser')

        if 'wp-content' in content or 'wp-includes' in content:
            detected_tech.add('WordPress')
        if soup.select_one('#react-root') or 'react.js' in content or 'react.min.js' in content:
            detected_tech.add('React')
        if soup.select_one('[ng-version]'):
            detected_tech.add('Angular')
        if soup.select_one('#app') and ('vue.js' in content or 'vue.min.js' in content):
             detected_tech.add('Vue.js')
        if 'jquery' in content:
            detected_tech.add('jQuery')
        if 'bootstrap' in content:
            detected_tech.add('Bootstrap')
        if 'X-Powered-By' in headers and 'ASP.NET' in headers['X-Powered-By']:
            detected_tech.add('ASP.NET')

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
            response = session.head(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'SiteScanner/1.0'})
            return url, response.status_code
        except requests.RequestException:
            return url, "Error"
    
    for url in urls:
        _, status = check_url(url)
        results[url] = status
    
    return jsonify({"link_statuses": results})


if __name__ == '__main__':
    load_proxies()
    app.run(port=5010, debug=True, threaded=True)

