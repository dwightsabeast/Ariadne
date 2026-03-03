# Ariadne

**Web Scanner, Mapper & Archiver**

A powerful reconnaissance and archiving tool that crawls websites, discovers subdomains, checks security headers, and preserves pages both locally and on the Wayback Machine — all from a clean dark-themed web UI.

---

## Features

| Category | Capabilities |
|---|---|
| **Site Scanning** | Recursive crawl with configurable depth (1-5), status codes, response times, content types, page titles, link extraction |
| **Subdomain Discovery** | Passive (crt.sh + DNS records) and active brute-force with wildcard detection |
| **Archiving** | Save to Archive.org, download pages locally with metadata headers |
| **Diff Detection** | Compare live pages against their latest Wayback Machine snapshot |
| **Security Analysis** | Audit 9 security headers (HSTS, CSP, X-Frame-Options, etc.) |
| **Broken Link Checker** | HEAD-request validation of all discovered links |
| **Export** | CSV export for scan results and subdomains, XML sitemap generation |
| **Scheduling** | Recurring scans with configurable intervals, depth, and archive options |
| **Proxy Support** | Load proxies from file with optional rotation |

---

## Prerequisites

- **Python 3.10+**
- pip (comes with Python)

---

## Quick Start

### Windows
```
start.bat
```

### Linux / macOS
```bash
chmod +x start.sh
./start.sh
```

Both scripts will create a virtual environment, install dependencies, and launch the backend on `http://localhost:5000`.

Open your browser to **http://localhost:5000** — the UI is served directly by Flask.

---

## Manual Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python backend.py
```

---

## Project Structure

```
ariadne/
├── backend.py          # Flask API server (all backend logic)
├── index.html          # Single-page frontend (HTML + CSS + JS)
├── requirements.txt    # Python dependencies
├── settings.json       # Scanner configuration
├── schedules.json      # Saved scan schedules
├── subdomains.txt      # Wordlist for brute-force discovery
├── proxies.txt         # Proxy list (one per line)
├── start.bat           # Windows launcher
├── start.sh            # Linux/macOS launcher
├── archives/           # Locally saved page snapshots
├── exports/            # CSV and sitemap output
└── logs/               # Application logs
```

---

## Configuration

Edit `settings.json` or use the Settings page in the UI:

| Setting | Default | Description |
|---|---|---|
| `max_depth` | 3 | Maximum crawl depth |
| `max_threads` | 10 | Concurrent threads for scanning |
| `request_timeout` | 15 | HTTP timeout in seconds |
| `delay_between_requests` | 0.2 | Pause between requests (seconds) |
| `follow_external` | false | Follow links to other domains |
| `user_agent` | Ariadne/1.0 | HTTP User-Agent string |
| `respect_robots` | true | Honor robots.txt |
| `subdomain_threads` | 20 | Threads for brute-force subdomain scan |
| `subdomain_timeout` | 5 | DNS resolution timeout |
| `proxy_enabled` | false | Route requests through proxies |
| `proxy_rotate` | false | Rotate through proxy list |

---

## Proxy Setup

Add proxies to `proxies.txt`, one per line:

```
http://proxy1:8080
socks5://proxy2:1080
http://user:pass@proxy3:3128
```

Enable in Settings and toggle proxy on.

---

## API Endpoints

All endpoints are prefixed with `/api`.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/scan/start` | Start a website scan |
| GET | `/scan/progress` | Poll scan progress |
| POST | `/scan/cancel` | Cancel running scan |
| GET | `/scan/results` | Get scan results |
| POST | `/subdomains/start` | Start subdomain discovery |
| GET | `/subdomains/progress` | Poll subdomain progress |
| GET | `/subdomains/results` | Get discovered subdomains |
| POST | `/archive/save` | Save URL(s) to Archive.org + local |
| POST | `/archive/check` | Check Wayback Machine availability |
| POST | `/archive/diff` | Diff live page vs latest snapshot |
| GET | `/archive/local/list` | List local archive files |
| GET | `/archive/local/<file>` | Download archived file |
| POST | `/tools/check-url` | Quick URL status + header check |
| POST | `/tools/broken-links` | Check all links from last scan |
| POST | `/export/csv` | Export results as CSV |
| POST | `/export/sitemap` | Generate XML sitemap |
| GET | `/schedules` | List all schedules |
| POST | `/schedules` | Create a schedule |
| DELETE | `/schedules/<id>` | Delete a schedule |
| POST | `/schedules/<id>/toggle` | Enable/disable schedule |
| GET | `/settings` | Get current settings |
| POST | `/settings` | Update settings |

---

## License

[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
