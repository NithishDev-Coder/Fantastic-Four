from flask import Flask, render_template, request
from modules.scope import validate_scope
from modules.subdomain import get_subdomains
from modules.portscan import scan_ports
from modules.technology import detect_technology
from modules.adminpanel import detect_admin_panels
from modules.risk import calculate_risk
from modules.report import generate_report

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    domain = request.form.get("domain")

    # Step 1 - Scope Validation
    scope_status = validate_scope(domain)

    if not scope_status:
        return render_template(
            "result.html",
            error="Target is not authorized for scanning."
        )

    # Step 2 - Recon Modules
    subdomains = get_subdomains(domain)
    ports = scan_ports(domain)
    technologies = detect_technology(domain)
    admin_panels = detect_admin_panels(domain)

    # Step 3 - Risk Analysis
    risk = calculate_risk(
        ports,
        admin_panels,
        technologies
    )

    # Step 4 - Report
    report = generate_report(
        domain,
        subdomains,
        ports,
        technologies,
        admin_panels,
        risk
    )

    return render_template(
        "result.html",
        report=report
    )


if __name__ == "__main__":
    app.run(debug=True)