"""
ReconGuard Web Application (Flask)

Serves the landing page, runs scans through ReconEngine, and exposes
both a browser flow and a JSON API.
"""

import json
import logging
import re

from flask import Flask, render_template, request, jsonify, Response, send_file, session
from modules.pdf_report import generate_pdf

from config import Config
from modules.engine import recon_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ReconGuard.App")

app = Flask(__name__)
app.config.from_object(Config)


def _safe_filename_part(value: str) -> str:
    """Strip anything unsafe to drop into a filename or response header."""
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", value or "target")
    return cleaned[:80] or "target"


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "on", "yes")


# ---------------------------------------------------------
# Landing page
# ---------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------
# Web form scan
# ---------------------------------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form.get("domain", "")
    authorized = _truthy(request.form.get("authorized", ""))
    logger.info(f"Web scan requested for '{domain}' (authorized={authorized})")

    success, result = recon_engine.run_recon(domain, authorized=authorized)

    if not success:
        logger.warning(f"Scan blocked/failed for '{domain}': {result}")
        return render_template("index.html", error=result, previous_domain=domain), 400

    report = result
    session["last_report"] = report
    return render_template(
        "dashboard.html",
        report=report,
        report_json=json.dumps(report, indent=2),
    )


# ---------------------------------------------------------
# REST API
# ---------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or request.form
    domain = data.get("domain", "")
    authorized = _truthy(data.get("authorized", ""))

    if not domain:
        return jsonify({"status": "error", "message": "Missing 'domain' parameter in request."}), 400

    success, result = recon_engine.run_recon(domain, authorized=authorized)

    if not success:
        return jsonify({"status": "error", "message": result}), 400

    return jsonify({"status": "success", "data": result}), 200


# ---------------------------------------------------------
# JSON report download
# ---------------------------------------------------------
@app.route("/download/json", methods=["POST"])
def download_json():
    report_raw = request.form.get("report_data", "{}")
    domain = _safe_filename_part(request.form.get("domain", "target_recon"))

    try:
        json.loads(report_raw)
    except (json.JSONDecodeError, TypeError):
        report_raw = "{}"

    return Response(
        report_raw,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={domain}_recon_report.json"},
    )


# ---------------------------------------------------------
# Error handlers
# ---------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", error="That page doesn't exist."), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}")
    return render_template("index.html", error="Something went wrong on our end. Try again."), 500

@app.route("/download/pdf")
def download_pdf():

    report = session.get("last_report")

    if not report:
        return "No report available", 404

    pdf = generate_pdf(report)

    return send_file(
        pdf,
        as_attachment=True,
        download_name="ReconGuard_Report.pdf",
        mimetype="application/pdf"
    )

if __name__ == "__main__":
    logger.info("Starting ReconGuard dev server...")
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
