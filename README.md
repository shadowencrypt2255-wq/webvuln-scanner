# Web Application Vulnerability Scanner

A Python tool that crawls a web application and automatically tests it for:

- **SQL Injection** — error-based and time-based blind detection across URL parameters and HTML forms
- **Cross-Site Scripting (XSS)** — reflected XSS detection across URL parameters and HTML forms
- **Broken Authentication** — weak/default credential login attempts, missing account lockout, insecure session cookie flags (`Secure`/`HttpOnly`/`SameSite`), and login forms submitted over plaintext HTTP
- Optional **OWASP ZAP** integration for a deeper spider + active scan pass, with ZAP alerts normalized into the same report

Findings are exported as JSON and a self-contained HTML report.

> **For authorized security testing only.** Only scan applications you own or have explicit written permission to test. This tool sends real attack payloads and login attempts to the target.

## Features

- Same-origin BFS crawler (`requests` + `BeautifulSoup`) that discovers pages and HTML forms
- Concurrent, rate-limited scanning (configurable threads and requests/second)
- Modular checks (`scanner/sqli.py`, `scanner/xss.py`, `scanner/auth.py`) that are easy to extend
- Optional OWASP ZAP spider + active scan via `python-owasp-zap-v2.4`
- JSON + HTML report output, colorized CLI summary
- Non-zero exit code when HIGH/CRITICAL findings are present (CI-friendly)
- Includes a deliberately vulnerable Flask testbed app to try the scanner safely

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Usage

```bash
python main.py http://target.example/ --i-have-authorization
```

Common options:

```bash
python main.py http://target.example/ \
  --i-have-authorization \
  --max-pages 200 \
  --threads 8 \
  --rps 5 \
  --skip-auth-bruteforce \
  --output-dir reports
```

Include an OWASP ZAP active scan (requires ZAP running locally with its API enabled):

```bash
python main.py http://target.example/ --i-have-authorization --use-zap --zap-api-key <key>
```

Reports are written to `reports/scan_report.json` and `reports/scan_report.html`.

## Try it locally against the included testbed

```bash
pip install -r requirements-dev.txt
python testbed/vulnerable_app.py
# in another terminal:
python main.py http://127.0.0.1:5000/ --i-have-authorization
```

This should surface SQL injection on `/search`, reflected XSS on `/comment`, and a
successful weak-credential login (`admin`/`admin`) on `/login`.

## Run tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Project layout

```
scanner/
  crawler.py      # site crawler (pages + forms)
  payloads.py      # SQLi/XSS payloads, SQL error signatures, weak credential list
  findings.py      # Finding / Severity data model
  sqli.py          # SQL injection checks
  xss.py           # reflected XSS checks
  auth.py          # broken authentication checks
  zap_client.py    # optional OWASP ZAP API integration
  engine.py         # crawl + concurrent scan orchestration, rate limiting
  report.py         # JSON/HTML report rendering
main.py             # CLI entrypoint
testbed/             # deliberately vulnerable Flask app for local testing
tests/               # pytest unit tests (mocked HTTP, no network)
```

## Disclaimer

This project is for educational and authorized security-testing purposes only
(e.g. your own applications, CTF targets, or engagements with written
authorization). The authors are not responsible for misuse.
