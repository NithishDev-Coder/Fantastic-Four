"""
Turns raw findings from the other modules into a risk score and a
ranked findings list. The scoring is deliberately simple and
explainable rather than "clever" -- every point on the score traces
back to one specific finding, and the report shows its work.
"""

import datetime

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

HIGH_RISK_SERVICES = {
    "MySQL", "PostgreSQL", "Redis", "MongoDB", "Elasticsearch",
    "MSSQL", "Oracle-DB", "Memcached", "CouchDB",
}
CRITICAL_RISK_SERVICES = {"Telnet", "RDP", "VNC"}

PANEL_RISK_OVERRIDES = {
    "/.env": "critical",
    "/.git/config": "critical",
    "/config.php.bak": "critical",
    "/actuator": "high",
    "/phpmyadmin": "high",
    "/pma": "high",
    "/manager/html": "high",
    "/actuator/health": "medium",
    "/server-status": "medium",
}

NON_PROD_LABELS = ("dev", "staging", "stage", "test", "uat", "old", "backup", "internal", "admin", "vpn")


def _score_ports(open_ports):
    findings = []
    for p in open_ports:
        service = p["service"]
        if service in CRITICAL_RISK_SERVICES:
            severity = "critical"
        elif service in HIGH_RISK_SERVICES or p["sensitive"]:
            severity = "high"
        elif service in ("HTTP", "HTTPS"):
            severity = "info"
        else:
            severity = "medium"
        findings.append({
            "type": "open_port",
            "severity": severity,
            "title": f"Port {p['port']} ({service}) is open",
            "detail": p["banner"] or "No banner grabbed.",
        })
    return findings


def _score_panels(panels):
    findings = []
    for panel in panels:
        severity = PANEL_RISK_OVERRIDES.get(panel["path"], "medium" if panel["status"] == 200 else "low")
        findings.append({
            "type": "exposed_panel",
            "severity": severity,
            "title": f"{panel['label']} reachable at {panel['path']} (HTTP {panel['status']})",
            "detail": panel["url"],
        })
    return findings


def _score_headers(tech):
    findings = []
    missing = [h for h, present in tech.get("security_headers", {}).items() if not present]
    if missing:
        readable = ", ".join(h.replace("-", " ").title() for h in missing)
        severity = "medium" if len(missing) >= 4 else "low"
        findings.append({
            "type": "missing_headers",
            "severity": severity,
            "title": f"{len(missing)} recommended security header(s) missing",
            "detail": readable,
        })
    return findings


def _score_subdomains(subdomains):
    findings = []
    for sub in subdomains:
        label = sub["host"].split(".")[0]
        if label in NON_PROD_LABELS:
            findings.append({
                "type": "exposed_subdomain",
                "severity": "low",
                "title": f"Non-production subdomain discovered: {sub['host']}",
                "detail": ", ".join(sub["ips"]) if sub["ips"] else "no A record",
            })
    return findings


def _score_domain_info(domain_info):
    findings = []
    if not domain_info or not domain_info.get("available"):
        return findings
    creation = domain_info.get("creation_date")
    if creation:
        try:
            created = datetime.datetime.strptime(creation, "%Y-%m-%d")
            age_days = (datetime.datetime.utcnow() - created).days
            if 0 <= age_days < 30:
                findings.append({
                    "type": "domain_age",
                    "severity": "medium",
                    "title": f"Domain was registered {age_days} day(s) ago",
                    "detail": f"Registered on {creation}",
                })
        except ValueError:
            pass
    return findings


def assess(subdomains, open_ports, tech, panels, domain_info=None):
    findings = []
    findings += _score_ports(open_ports)
    findings += _score_panels(panels)
    findings += _score_headers(tech)
    findings += _score_subdomains(subdomains)
    findings += _score_domain_info(domain_info)

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))

    score = min(100, sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings))

    if score >= 60:
        rating = "Critical"
    elif score >= 35:
        rating = "High"
    elif score >= 15:
        rating = "Medium"
    elif score > 0:
        rating = "Low"
    else:
        rating = "Minimal"

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    return {"score": score, "rating": rating, "findings": findings, "counts": counts}

def generate_recommendations(report):
    """
    Generate AI security recommendations from existing findings.
    """

    recommendations = []

    findings = report.get("risk", {}).get("findings", [])

    for finding in findings:

        if finding["type"] == "open_port":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Restrict Exposed Service",
                "reason": finding["title"],
                "recommendation":
                    "Close the port if it is not required. Otherwise restrict access using a firewall, VPN or IP allow-list."
            })

        elif finding["type"] == "missing_headers":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Enable Missing Security Headers",
                "reason": finding["detail"],
                "recommendation":
                    "Configure all recommended HTTP security headers such as CSP, HSTS and X-Frame-Options."
            })

        elif finding["type"] == "exposed_panel":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Protect Administrative Interfaces",
                "reason": finding["title"],
                "recommendation":
                    "Restrict administrative interfaces using authentication, VPN, IP allow-list and Multi-Factor Authentication."
            })

        elif finding["type"] == "domain_age":

            recommendations.append({
                "priority": "Medium",
                "title": "Monitor Newly Registered Domain",
                "reason": finding["title"],
                "recommendation":
                    "Monitor DNS changes, certificate updates and reputation because newly registered domains deserve closer observation."
            })

        elif finding["type"] == "exposed_subdomain":

            recommendations.append({
                "priority": "Low",
                "title": "Review Non-Production Subdomain",
                "reason": finding["title"],
                "recommendation":
                    "Remove unused development or staging environments or restrict public access."
            })

    return recommendations