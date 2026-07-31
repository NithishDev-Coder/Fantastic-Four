from flask import Flask, jsonify, render_template, request

from scanner import run_scan

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    authorized = bool(data.get("authorized", False))

    if not authorized:
        return jsonify({"error": "Authorization confirmation is required before scanning."}), 400

    try:
        result = run_scan(target, authorized)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive fallback
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
