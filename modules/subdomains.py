"""
Subdomain enumeration.

Two sources, combined and deduped:
  - Certificate Transparency logs via crt.sh. Fully passive -- this
    never sends a single packet to the target itself.
  - A DNS brute force against a short list of common subdomain names,
    threaded but capped so it stays quick and doesn't hammer the
    target's DNS infrastructure.
"""

import concurrent.futures

import dns.resolver
import requests

from modules.request_helper import safe_get

CT_LOG_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CT_TIMEOUT = 12
DNS_TIMEOUT = 3
MAX_WORKERS = 20

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
    "api", "dev", "staging", "stage", "test", "uat", "qa", "beta",
    "admin", "portal", "app", "apps", "mobile", "m", "cdn", "static",
    "assets", "media", "img", "images", "docs", "help", "support",
    "blog", "shop", "store", "secure", "vpn", "remote", "gateway",
    "internal", "intranet", "git", "gitlab", "jenkins", "ci", "monitor",
    "grafana", "kibana", "status", "demo", "sandbox", "old", "new",
    "backup", "db", "database", "mysql", "sql", "cpanel", "webdisk",
    "autodiscover", "owa", "exchange", "dashboard", "panel",
]


def _query_crtsh(domain):
    """Passive lookup. Failures here are non-fatal -- we fall back to brute force."""
    found = set()
    try:
        resp = safe_get(CT_LOG_URL.format(domain=domain))
        if resp.status_code == 200 and resp.text.strip():
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and name != domain:
                        found.add(name)
    except (requests.RequestException, ValueError):
        pass
    return found


def _resolve(hostname):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        return [str(a) for a in resolver.resolve(hostname, "A")]
    except Exception:
        return None


def _resolve_many(hosts):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_resolve, host): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            ips = future.result()
            if ips:
                results[host] = ips
    return results


def enumerate_subdomains(domain):
    """Returns a list of {"host", "ips", "source"} dicts, sorted by host."""
    results = {}

    brute_hits = _resolve_many([f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS])
    for host, ips in brute_hits.items():
        results[host] = {"host": host, "ips": ips, "source": "dns-bruteforce"}

    passive_hits = _query_crtsh(domain)
    unresolved = [h for h in passive_hits if h not in results]
    if unresolved:
        resolved = _resolve_many(unresolved)
        for host in unresolved:
            results[host] = {
                "host": host,
                "ips": resolved.get(host, []),
                "source": "cert-transparency",
            }

    root_ips = _resolve(domain) or []
    results[domain] = {"host": domain, "ips": root_ips, "source": "apex"}

    return sorted(results.values(), key=lambda r: r["host"])
