"""
Exposed admin/management panel detection.

Checks a curated list of well-known paths and flags anything that
doesn't come back as a plain 404/connection error. Deliberately a
short, GET-only list -- a handful of requests per scheme, not a
directory brute force.
"""

import concurrent.futures

import requests

from modules.request_helper import safe_get

USER_AGENT = "ReconGuard/2.0 (authorized-recon)"
REQUEST_TIMEOUT = 6
MAX_WORKERS = 8

CANDIDATE_PATHS = [
    ("/admin", "Generic admin panel"),
    ("/administrator", "Joomla admin panel"),
    ("/wp-admin", "WordPress admin panel"),
    ("/wp-login.php", "WordPress login"),
    ("/login", "Generic login page"),
    ("/cpanel", "cPanel"),
    ("/phpmyadmin", "phpMyAdmin"),
    ("/pma", "phpMyAdmin (short path)"),
    ("/manager/html", "Tomcat manager"),
    ("/server-status", "Apache server-status"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/health", "Spring Boot Actuator health"),
    ("/.env", "Exposed .env file"),
    ("/.git/config", "Exposed .git directory"),
    ("/config.php.bak", "Backup config file"),
    ("/dashboard", "Generic dashboard"),
    ("/panel", "Generic control panel"),
    ("/webmail", "Webmail login"),
    ("/portainer", "Portainer"),
    ("/grafana", "Grafana"),
    ("/kibana", "Kibana"),
    ("/jenkins", "Jenkins"),
    ("/swagger-ui.html", "Exposed Swagger UI"),
    ("/api/swagger.json", "Exposed API schema"),
]

INTERESTING_STATUS = {200, 201, 301, 302, 401, 403}


def _probe(base_url, path, label):
    try:
        resp = safe_get(base_url + path)
    except requests.RequestException:
        return None
    if resp.status_code in INTERESTING_STATUS:
        return {
            "path": path,
            "label": label,
            "status": resp.status_code,
            "url": base_url + path,
        }
    return None


def find_panels(domain):
    findings = {}
    for scheme in ("https://", "http://"):
        base_url = f"{scheme}{domain}"
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(_probe, base_url, path, label) for path, label in CANDIDATE_PATHS]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result["path"] not in findings:
                    findings[result["path"]] = result
        if findings:
            break  # https worked, no need to repeat over plain http

    return sorted(findings.values(), key=lambda f: f["path"])
