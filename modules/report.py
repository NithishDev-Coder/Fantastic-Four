"""
Assembles the final report dict that gets handed back to the Flask
layer, rendered into the dashboard, and offered as a JSON download.
"""

from modules.risk import generate_recommendations
import datetime


def build_report(domain, subdomains, open_ports, tech, panels, risk, domain_info=None):

    report = {
        "target": domain,
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),

        "summary": {
            "subdomains_found": len(subdomains),
            "open_ports_found": len(open_ports),
            "technologies_detected": sum(
                len(v) for v in tech.get("detected", {}).values()
            ),
            "exposed_panels_found": len(panels),
            "risk_score": risk["score"],
            "risk_rating": risk["rating"],
        },

        "subdomains": subdomains,
        "open_ports": open_ports,
        "tech_stack": tech,
        "exposed_panels": panels,
        "domain_info": domain_info or {"available": False},
        "risk": risk,
    }

    # Generate AI recommendations
    report["recommendations"] = generate_recommendations(report)

    return report