# ReconGuard

**Team Fantastic-Four**

## Problem statement

Domain: Red Teaming

Build a tool that automates external recon (subdomains, open ports, tech stack,
exposed panels) against a target you own/are authorized on.

Requirements:
- subdomain enum
- port/service scan
- tech fingerprinting
- exposed admin panel detection
- risk-ranked report
- scope allowlist enforcement
- rate-limit respectful

## What it does

Point ReconGuard at a domain and, after you confirm you're authorized to test
it, it runs the target through five checks and rolls the results into one
risk-ranked report:

1. **Scope validation** — rejects invalid domains, private/loopback
   addresses, and anything on a protected denylist before a single scan
   packet goes out. Optional allowlist mode locks the tool to a fixed set of
   domains.
2. **Subdomain enumeration** — certificate-transparency logs (passive) plus a
   throttled DNS brute force (active) against a common wordlist.
3. **Port & service scan** — a threaded TCP-connect scan against ~35
   commonly-relevant ports (not a full 65535-port sweep), with light banner
   grabbing.
4. **Technology fingerprinting** — CMS, JS/CSS frameworks, server software,
   CDN, analytics, and e-commerce platforms detected from response headers
   and page markup, plus a check for the standard security response headers.
5. **Exposed panel detection** — checks ~24 well-known paths (admin logins,
   database consoles, `.env`/`.git` leaks, monitoring dashboards) for
   anything other than a clean 404.

A WHOIS lookup adds registrar/registration-date context, and everything
feeds into a simple, explainable risk score (each point traces back to a
specific finding) with a Critical/High/Medium/Low/Minimal rating.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`. Enter a domain, tick the authorization
checkbox, and run the scan. Results are also available as JSON:

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "authorized": true}'
```

### Configuration

All of it lives in `config.py` / environment variables:

| Variable            | Default | Purpose                                            |
|---------------------|---------|-----------------------------------------------------|
| `SECRET_KEY`        | random per process | Flask session signing key                |
| `FLASK_DEBUG`       | `False` | Enables Flask's debug/reloader mode                |
| `ALLOWLIST_ENFORCED`| `False` | Restrict scans to `ALLOWED_DOMAINS`                |
| `ALLOWED_DOMAINS`   | *(empty)* | Comma-separated list of domains, used when the allowlist is enforced |

## Project layout

```
app.py                  Flask routes
config.py                App configuration
modules/
  scope.py                Domain validation, allowlist/denylist, authorization gate
  subdomains.py            CT-log + DNS brute-force subdomain enumeration
  ports.py                 TCP-connect port/service scan
  techstack.py              Header + markup based tech fingerprinting
  panels.py                 Exposed admin/management panel checks
  domain_info.py            WHOIS lookup
  risk.py                   Finding scoring and risk rating
  report.py                 Final report assembly
  engine.py                 Orchestrates the above and returns one report
templates/               Jinja templates (landing page, results dashboard)
static/                  CSS/JS for the dashboard
```

## Responsible use

ReconGuard is built to only run against domains you own or have explicit
permission to test. It refuses obviously out-of-scope targets (protected
suffixes, private/loopback addresses, a small denylist of apex domains) and
requires an explicit authorization confirmation before any scan starts. It
doesn't do anything beyond passive lookups and read-only requests to a small,
fixed set of ports/paths — no exploitation, no credential guessing, no
write requests.
