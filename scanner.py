import re
import socket
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import dns.resolver

COMMON_PORTS: List[Tuple[int, str]] = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3306, "MySQL"),
    (8080, "HTTP Alternate"),
    (8443, "HTTPS Alternate"),
]

SUBDOMAIN_PREFIXES = ["www", "api", "admin", "dev", "test", "staging", "portal", "app"]


def normalize_target(target: str) -> str:
    if not target or not isinstance(target, str):
        raise ValueError("A target domain is required.")

    raw = target.strip().lower()
    if not raw:
        raise ValueError("A target domain is required.")

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw
    if not host:
        raise ValueError("Invalid target domain.")

    host = host.strip().rstrip(".")
    if host.startswith("www.") and "." in host[4:]:
        host = host[4:]

    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host, re.IGNORECASE):
        raise ValueError("Only standard domains such as example.com are supported.")

    return host


def is_in_scope(target: str, candidate: str) -> bool:
    target = normalize_target(target)
    candidate = normalize_target(candidate)
    return candidate == target or candidate.endswith(f".{target}")


def resolve_hostname(hostname: str) -> Dict[str, object]:
    try:
        answers = dns.resolver.resolve(hostname, "A", lifetime=2)
        ip = str(answers[0])
        return {"hostname": hostname, "ip": ip, "status": "Resolved"}
    except dns.resolver.NXDOMAIN:
        return {"hostname": hostname, "ip": None, "status": "No record"}
    except dns.resolver.NoAnswer:
        return {"hostname": hostname, "ip": None, "status": "No record"}
    except Exception as exc:  # pragma: no cover - network / resolver failure
        return {"hostname": hostname, "ip": None, "status": "DNS resolution failed", "error": str(exc)}


def resolve_target(target: str) -> Dict[str, object]:
    normalized = normalize_target(target)
    try:
        ip = socket.gethostbyname(normalized)
        return {"target": normalized, "ip": ip, "status": "Reachable"}
    except socket.gaierror as exc:
        return {"target": normalized, "ip": None, "status": "DNS resolution failed", "error": str(exc)}


def discover_subdomains(target: str) -> List[Dict[str, object]]:
    normalized = normalize_target(target)
    discovered: List[Dict[str, object]] = []
    for prefix in SUBDOMAIN_PREFIXES:
        hostname = f"{prefix}.{normalized}"
        if not is_in_scope(normalized, hostname):
            continue
        result = resolve_hostname(hostname)
        if result.get("status") == "Resolved" and result.get("ip"):
            discovered.append(result)
        time.sleep(0.05)
    return discovered


def scan_ports(target: str, host_ip: str) -> List[Dict[str, object]]:
    ports: List[Dict[str, object]] = []
    for port, service in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        try:
            result = sock.connect_ex((host_ip or target, port))
            if result == 0:
                ports.append({"port": port, "service": service})
        except OSError:
            pass
        finally:
            sock.close()
        time.sleep(0.05)
    return ports


def run_scan(target: str, authorized: bool = True) -> Dict[str, object]:
    if not authorized:
        raise ValueError("Authorization confirmation is required.")

    normalized = normalize_target(target)
    resolution = resolve_target(normalized)
    subdomains = discover_subdomains(normalized)

    host_ip = resolution.get("ip")
    open_ports = []
    if host_ip:
        open_ports = scan_ports(normalized, host_ip)

    return {
        "target": normalized,
        "ip": resolution.get("ip"),
        "status": resolution.get("status"),
        "subdomains": subdomains,
        "ports": open_ports,
        "summary": {
            "subdomains_found": len(subdomains),
            "open_ports": len(open_ports),
        },
    }
