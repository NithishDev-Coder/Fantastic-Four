# ReconGuard

ReconGuard is a small, authorized external reconnaissance MVP built with Flask. It validates a target domain, resolves the primary host, discovers a handful of common subdomains, and scans a small set of common TCP ports without executing exploits or performing destructive actions.

## Current MVP capabilities

- Domain input and normalization
- Authorization confirmation gate
- DNS resolution for the target
- Discovery of a limited set of subdomains (`www`, `api`, `admin`, `dev`, `test`, `staging`, `portal`, `app`)
- TCP scanning of common ports (`21`, `22`, `25`, `53`, `80`, `443`, `3306`, `8080`, `8443`)
- A simple dark-themed dashboard with loading states

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000

## Limitations

- This is a reconnaissance-only MVP.
- It does not attempt exploitation, credential attacks, brute forcing, or vulnerability scanning.
- Subdomain discovery is intentionally limited and respectful.

## Future roadmap

### Phase 2
- Better passive subdomain enumeration
- Scan discovered subdomains
- Technology fingerprinting
- HTTP header analysis
- Admin panel detection
- Better rate limiting

### Phase 3
- Risk scoring and ranking
- JSON/PDF reports
- Scan history
- Screenshots

### Phase 4
- Nmap integration
- Subfinder / Amass
- Nuclei
- CVE/CVSS correlation
