"""
CloudGuard - Flask Backend

Mode Toggle: Scan (discover) vs Red-Team (exploit)
"""

from flask import Flask, render_template, request, jsonify
from scanner import AWSScanner, AzureScanner, GCPScanner, CloudProvider
from exploiter import AWSExploiter, AzureExploiter, GCPExploiter
from result_model import (
    EnhancedFinding,
    CategoryResults,
    ScanSummary,
    FindingStatus,
    map_severity_to_status,
    calculate_confidence,
    get_cis_category,
    get_category_name,
)
import os
from dotenv import load_dotenv
from collections import defaultdict

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


@app.after_request
def set_cache_headers(response):
    """Prevent caching of all responses"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/")
def index():
    """Serve UI with mode toggle"""
    return render_template("index.html")


def transform_findings_to_summary(provider: str, findings: list) -> dict:
    """
    Transform raw scan findings into categorized summary (llmguardt2-style)
    """
    # Convert to enhanced findings with status + confidence
    enhanced = []
    for f in findings:
        status = map_severity_to_status(f.severity, f.is_vulnerable)
        confidence = calculate_confidence(f.severity, f.is_vulnerable)
        category = get_cis_category(f.cis_control)
        
        enhanced.append(
            EnhancedFinding(
                check_id=f.check_id,
                check_name=f.check_name,
                resource=f.resource,
                status=status,
                confidence=confidence,
                cis_control=f.cis_control,
                cis_category=category,
                severity_original=f.severity,
                finding=f.finding,
                remediation=f.remediation,
                is_vulnerable=f.is_vulnerable,
            )
        )
    
    # Group by CIS category
    by_category = defaultdict(list)
    for finding in enhanced:
        by_category[finding.cis_category].append(finding)
    
    # Build category results
    category_results = []
    vulnerable_total = 0
    partial_total = 0
    resistant_total = 0
    review_total = 0
    
    for category in sorted(by_category.keys(), key=lambda x: x.value):
        findings_in_cat = by_category[category]
        resistant = len([f for f in findings_in_cat if f.status == FindingStatus.RESISTANT])
        vulnerable = len([f for f in findings_in_cat if f.status == FindingStatus.VULNERABLE])
        partial = len([f for f in findings_in_cat if f.status == FindingStatus.PARTIAL])
        review = len([f for f in findings_in_cat if f.status == FindingStatus.REVIEW])
        
        compliance_pct = (resistant / len(findings_in_cat) * 100) if findings_in_cat else 100
        
        vulnerable_total += vulnerable
        partial_total += partial
        resistant_total += resistant
        review_total += review
        
        category_results.append(
            CategoryResults(
                category=category,
                category_name=get_category_name(category),
                findings=findings_in_cat,
                compliance_percentage=int(compliance_pct),
                count_vulnerable=vulnerable,
                count_partial=partial,
                count_resistant=resistant,
                count_review=review,
            )
        )
    
    # Calculate overall metrics
    total = len(enhanced)
    overall_compliance = (resistant_total / total * 100) if total > 0 else 100
    overall_risk = 100 - overall_compliance
    
    # Count by severity
    critical = len([f for f in enhanced if f.severity_original.lower() == "critical"])
    high = len([f for f in enhanced if f.severity_original.lower() == "high"])
    medium = len([f for f in enhanced if f.severity_original.lower() == "medium"])
    low = len([f for f in enhanced if f.severity_original.lower() == "low"])
    
    summary = ScanSummary(
        provider=provider,
        scan_type="scan",
        overall_compliance=int(overall_compliance),
        overall_risk_score=int(overall_risk),
        total_findings=total,
        categories=category_results,
        vulnerable_count=vulnerable_total,
        partial_count=partial_total,
        resistant_count=resistant_total,
        review_count=review_total,
        critical_issues=critical,
        high_issues=high,
        medium_issues=medium,
        low_issues=low,
    )
    
    return summary.model_dump()


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
    
    # Transform to llmguardt2-style summary
    summary = transform_findings_to_summary(provider, findings)

    return jsonify(summary)


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
