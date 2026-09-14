"""
SupplyShield - Executive Security Audit Report Generator
Generates structured JSON and printable HTML security audit reports for scan results,
including MITRE ATT&CK mapping, SLSA rating, findings list, and remediation guidance.
"""

from typing import Dict, Any
import datetime
import html

def generate_json_report(scan_record: Dict[str, Any]) -> Dict[str, Any]:
    """Generates an executive JSON security report for compliance & CI/CD tools."""
    scan_id_val = scan_record.get("scan_id") or scan_record.get("id") or "0000"
    risk_score = scan_record.get("composite_risk_score", scan_record.get("composite_score", 0))
    verdict = scan_record.get("verdict", "UNKNOWN")
    slsa_level = scan_record.get("slsa_security_level", scan_record.get("slsa_level", "SLSA-Level-0"))
    findings = scan_record.get("findings", scan_record.get("static_findings", []))
    
    mitre_techniques = set()
    for f in findings:
        t_id = f.get("mitre_id")
        if t_id:
            mitre_techniques.add(t_id)

    remediations = []
    if verdict == "CRITICAL_MALICIOUS":
        remediations.append("DO NOT INSTALL OR EXECUTE THIS PACKAGE. Quarantine immediately.")
        remediations.append("Revoke any credentials or environment variables accessed by this package.")
        remediations.append("Inspect system process tree for unauthorized subprocess creation.")
    elif verdict == "SUSPICIOUS":
        remediations.append("Review suspicious dynamic calls (eval/exec/socket) before deployment.")
        remediations.append("Run package in an isolated sandbox environment.")
    else:
        remediations.append("Package passed baseline security audit. Safe for deployment.")

    return {
        "report_id": f"REP-{scan_id_val}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": scan_record.get("package_name") or scan_record.get("filename") or "Code Snippet",
        "executive_summary": {
            "risk_score": risk_score,
            "verdict": verdict,
            "slsa_provenance_level": slsa_level,
            "total_findings": len(findings),
            "critical_findings": len([f for f in findings if f.get("severity") == "CRITICAL"]),
            "high_findings": len([f for f in findings if f.get("severity") == "HIGH"]),
            "mitre_techniques_detected": sorted(list(mitre_techniques))
        },
        "findings": findings,
        "remediation_guidance": remediations
    }

def generate_html_report(scan_record: Dict[str, Any]) -> str:
    """Generates a standalone, print-ready HTML security audit report."""
    report_data = generate_json_report(scan_record)
    summary = report_data["executive_summary"]
    findings = report_data["findings"]
    remediations = report_data["remediation_guidance"]

    badge_color = "#10B981" if summary["verdict"] == "CLEAN" else "#F59E0B" if summary["verdict"] == "SUSPICIOUS" else "#EF4444"

    findings_rows = ""
    for f in findings:
        sev_color = "#EF4444" if f.get("severity") == "CRITICAL" else "#F59E0B" if f.get("severity") == "HIGH" else "#3B82F6"
        findings_rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #334155;"><span style="background:{sev_color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;">{html.escape(str(f.get("severity", "")))}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-weight: bold;">{html.escape(str(f.get("rule_id", "")))}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{html.escape(str(f.get("description", "")))}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-family: monospace; color: #38BDF8;">{html.escape(str(f.get("mitre_id", "N/A")))}</td>
        </tr>
        """

    if not findings_rows:
        findings_rows = '<tr><td colspan="4" style="padding: 15px; text-align: center; color: #10B981;">No security vulnerabilities detected. Package is clean.</td></tr>'

    remediation_items = "".join([f"<li style='margin-bottom: 8px;'>{html.escape(r)}</li>" for r in remediations])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SupplyShield Security Audit Report - {html.escape(report_data['report_id'])}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0F172A; color: #F8FAFC; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1E293B; border-radius: 12px; padding: 32px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 24px; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38BDF8; display: flex; align-items: center; gap: 10px; }}
        .badge {{ background: {badge_color}; color: white; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: #0F172A; padding: 16px; border-radius: 8px; border: 1px solid #334155; text-align: center; }}
        .card-val {{ font-size: 24px; font-weight: bold; margin-top: 6px; color: #F8FAFC; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #0F172A; border-radius: 8px; overflow: hidden; }}
        th {{ background: #334155; color: #94A3B8; text-align: left; padding: 12px; font-size: 13px; text-transform: uppercase; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #F8FAFC; margin-top: 28px; margin-bottom: 12px; border-left: 4px solid #38BDF8; padding-left: 10px; }}
        ul {{ background: #0F172A; padding: 20px 20px 20px 40px; border-radius: 8px; border: 1px solid #334155; color: #CBD5E1; }}
        .footer {{ margin-top: 40px; text-align: center; font-size: 12px; color: #64748B; border-top: 1px solid #334155; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🛡️ SupplyShield Security Audit Report</div>
            <div class="badge">{html.escape(summary['verdict'])}</div>
        </div>

        <div style="margin-bottom: 24px; color: #94A3B8; font-size: 14px;">
            <strong>Target:</strong> {html.escape(report_data['target'])} &nbsp;|&nbsp; 
            <strong>Report ID:</strong> {html.escape(report_data['report_id'])} &nbsp;|&nbsp; 
            <strong>Generated:</strong> {html.escape(report_data['timestamp'])}
        </div>

        <div class="grid">
            <div class="card">
                <div style="color:#94A3B8; font-size:12px;">RISK SCORE</div>
                <div class="card-val" style="color:{badge_color}">{summary['risk_score']} / 100</div>
            </div>
            <div class="card">
                <div style="color:#94A3B8; font-size:12px;">SLSA LEVEL</div>
                <div class="card-val" style="color:#38BDF8">{html.escape(summary['slsa_provenance_level'])}</div>
            </div>
            <div class="card">
                <div style="color:#94A3B8; font-size:12px;">CRITICAL FINDINGS</div>
                <div class="card-val" style="color:#EF4444">{summary['critical_findings']}</div>
            </div>
            <div class="card">
                <div style="color:#94A3B8; font-size:12px;">TOTAL FINDINGS</div>
                <div class="card-val">{summary['total_findings']}</div>
            </div>
        </div>

        <div class="section-title">Detailed Vulnerability Findings</div>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule ID</th>
                    <th>Description</th>
                    <th>MITRE ATT&CK</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <div class="section-title">Remediation & Action Plan</div>
        <ul>
            {remediation_items}
        </ul>

        <div class="footer">
            Generated automatically by SupplyShield Autonomous Supply-Chain Security Engine.
        </div>
    </div>
</body>
</html>
"""
    return html_content
