"""
AI Recommendation Engine
"""

def generate(report):

    recommendations = []

    # Risk findings
    for finding in report["risk"]["findings"]:

        if finding["type"] == "open_port":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Review Open Port",
                "reason": finding["title"],
                "recommendation": "Close unused ports or restrict them using a firewall."
            })

        elif finding["type"] == "missing_headers":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Enable Security Headers",
                "reason": finding["detail"],
                "recommendation": "Enable the missing HTTP security headers."
            })

        elif finding["type"] == "exposed_panel":

            recommendations.append({
                "priority": finding["severity"].capitalize(),
                "title": "Protect Admin Panel",
                "reason": finding["title"],
                "recommendation": "Restrict access using VPN, IP allow-list or MFA."
            })

        elif finding["type"] == "exposed_subdomain":

            recommendations.append({
                "priority": "Low",
                "title": "Review Non-Production Asset",
                "reason": finding["title"],
                "recommendation": "Remove or restrict unused development or staging systems."
            })

        elif finding["type"] == "domain_age":

            recommendations.append({
                "priority": "Medium",
                "title": "Monitor Newly Registered Domain",
                "reason": finding["title"],
                "recommendation": "Closely monitor DNS, TLS certificates and infrastructure."
            })

    return recommendations