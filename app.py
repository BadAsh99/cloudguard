"""
CloudGuard - Flask Backend

Mode Toggle: Scan (discover) vs Red-Team (exploit)
"""

from flask import Flask, render_template, request, jsonify
from scanner import AWSScanner, AzureScanner, GCPScanner, CloudProvider
from exploiter import AWSExploiter, AzureExploiter, GCPExploiter
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Initialize scanners
scanners = {
    "aws": AWSScanner(),
    "azure": AzureScanner(),
    "gcp": GCPScanner(),
}

# Initialize exploiters
exploiters = {
    "aws": AWSExploiter(),
    "azure": AzureExploiter(),
    "gcp": GCPExploiter(),
}


@app.route("/")
def index():
    """Serve UI with mode toggle"""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Execute scan (read-only discovery)
    
    POST body:
    {
        "provider": "aws|azure|gcp",
        "credentials": {...},
        "mode": "scan"
    }
    """
    data = request.json
    provider = data.get("provider", "").lower()
    mode = data.get("mode", "scan")

    if provider not in scanners:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    if mode != "scan":
        return jsonify({"error": "Invalid mode for /scan endpoint"}), 400

    scanner = scanners[provider]
    credentials = data.get("credentials", {})

    # Execute scan
    findings = scanner.scan(credentials)
    risk_metrics = scanner.score_risk(findings)

    return jsonify(
        {
            "provider": provider,
            "mode": "scan",
            "findings": [f.dict() for f in findings],
            "risk_metrics": risk_metrics,
        }
    )


@app.route("/api/redteam", methods=["POST"])
def redteam():
    """
    Execute red-team exploitation (active)
    
    POST body:
    {
        "provider": "aws|azure|gcp",
        "credentials": {...},
        "mode": "redteam",
        "findings": [...]  # From scan phase
    }
    """
    data = request.json
    provider = data.get("provider", "").lower()
    mode = data.get("mode", "redteam")

    if provider not in exploiters:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    if mode != "redteam":
        return jsonify({"error": "Invalid mode for /redteam endpoint"}), 400

    # Security warning: Require explicit confirmation
    if not data.get("confirm_exploitation"):
        return (
            jsonify(
                {
                    "error": "Red-team mode requires explicit confirmation",
                    "warning": "This will execute active exploitation against real resources",
                }
            ),
            403,
        )

    exploiter = exploiters[provider]
    credentials = data.get("credentials", {})
    findings = data.get("findings", [])

    # Execute exploits
    exploit_results = []
    for finding in findings:
        result = exploiter.exploit(finding, credentials)
        exploit_results.append(result)

    # Build attack chains
    attack_chains = exploiter.build_attack_chain(findings)

    # Simulate impact
    impact = exploiter.simulate_impact(exploit_results)

    return jsonify(
        {
            "provider": provider,
            "mode": "redteam",
            "exploit_results": [r.dict() for r in exploit_results],
            "attack_chains": attack_chains,
            "impact_simulation": impact,
        }
    )


@app.route("/api/payloads/<provider>", methods=["GET"])
def get_payloads(provider):
    """Fetch available payloads for a provider"""
    provider = provider.lower()
    if provider not in scanners:
        return jsonify({"error": f"Unknown provider: {provider}"}), 400

    scanner = scanners[provider]
    payloads = [p.dict() for p in scanner.payloads]

    return jsonify({"provider": provider, "payloads": payloads})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "0.1.0"})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
