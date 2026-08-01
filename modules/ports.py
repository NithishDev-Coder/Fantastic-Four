"""
Port and service scanning.

A plain TCP-connect scan against a curated list of ports worth
knowing about, not a full 1-65535 sweep -- that's slow and more
aggressive than this tool needs to be, even against something you're
authorized to test. Threaded with a short per-connection timeout so
one unresponsive host doesn't stall the rest of the scan.
"""

import concurrent.futures
import socket

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS", 3000: "Dev-Server",
    3306: "MySQL", 3389: "RDP", 5000: "Dev-Server", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API",
    7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "PHP-FPM/Dev",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

SENSITIVE_PORTS = {
    3306, 5432, 6379, 27017, 27018, 9200, 9300, 11211,
    1433, 1521, 5984, 2049, 3389, 5900, 23, 6443,
}

CONNECT_TIMEOUT = 1.2
MAX_WORKERS = 25


def _probe_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            banner = ""
            try:
                sock.settimeout(0.8)
                banner = sock.recv(128).decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass
            return port, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(host):
    """Returns a list of {"port", "service", "banner", "sensitive"} dicts."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_probe_port, host, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                port, banner = result
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "banner": banner,
                    "sensitive": port in SENSITIVE_PORTS,
                })
    return sorted(open_ports, key=lambda p: p["port"])
