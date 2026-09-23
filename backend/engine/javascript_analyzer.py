"""
SupplyShield - Multi-Language Engine: JavaScript & Node.js Manifest Analyzer
Detects malicious npm package lifecycle hooks (preinstall, postinstall),
command injection, network socket exfiltration, and dynamic code evaluation (eval/Function).
"""

import json
import re
from typing import Dict, List, Any

# Dangerous npm lifecycle scripts commonly abused in supply-chain attacks
DANGEROUS_LIFECYCLE_HOOKS = ["preinstall", "postinstall", "install", "preuninstall", "postuninstall"]

# Suspicious CLI execution patterns inside npm package scripts
DANGEROUS_CLI_PATTERNS = [
    (r"curl\s+.*\|\s*(sh|bash)", "JS-LIFE-001", "CRITICAL", "Pipe to Shell Execution in Lifecycle Hook", "T1059.004"),
    (r"wget\s+.*\|\s*(sh|bash)", "JS-LIFE-001", "CRITICAL", "Pipe to Shell Execution in Lifecycle Hook", "T1059.004"),
    (r"powershell\s+-enc", "JS-LIFE-002", "CRITICAL", "Encoded PowerShell Command Execution", "T1027"),
    (r"node\s+-e\s+['\"].*eval", "JS-LIFE-003", "HIGH", "Dynamic Node.js Eval Execution in Lifecycle Hook", "T1059.007"),
    (r"bash\s+-i\s+>&", "JS-LIFE-004", "CRITICAL", "Reverse Shell Invocation in Lifecycle Script", "T1059.004"),
    (r"nc\s+.*-e", "JS-LIFE-004", "CRITICAL", "Netcat Reverse Shell Invocation", "T1059.004")
]

# Suspicious JavaScript AST/regex patterns in .js files
JS_CODE_PATTERNS = [
    (r"eval\s*\(", "JS-DYN-001", "CRITICAL", "Dynamic JavaScript Code Evaluation via eval()", "T1059.007"),
    (r"Function\s*\(\s*['\"`]return\s+this['\"`]\s*\)", "JS-DYN-002", "HIGH", "Global Context Escape via Function() constructor", "T1059.007"),
    (r"(child_process\s*\.\s*(exec|spawn|execFile|fork)|require\s*\(\s*['\"]child_process['\"]\s*\))", "JS-SYS-001", "CRITICAL", "Subprocess Execution via Node.js child_process", "T1059"),
    (r"net\s*\.\s*(connect|createConnection)", "JS-NET-001", "HIGH", "Low-Level TCP Socket Connection via net module", "T1071"),
    (r"process\s*\.\s*env", "JS-CRED-001", "MEDIUM", "Access to Node.js Process Environment Variables", "T1552.001"),
    (r"fs\s*\.\s*(readFileSync|writeFileSync|unlinkSync)\s*\(\s*['\"`].*(id_rsa|aws|env|credentials)", "JS-CRED-002", "CRITICAL", "Sensitive Credential File System Access", "T1552.001")
]


def analyze_npm_manifest(manifest_content: str) -> Dict[str, Any]:
    """Analyzes package.json npm manifest files for malicious lifecycle hooks."""
    findings: List[Dict[str, Any]] = []
    scripts_found: Dict[str, str] = {}

    try:
        manifest = json.loads(manifest_content)
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid package.json format: {str(e)}",
            "findings": []
        }

    package_name = manifest.get("name", "unknown-npm-package")
    version = manifest.get("version", "0.0.0")
    scripts = manifest.get("scripts", {})

    for hook in DANGEROUS_LIFECYCLE_HOOKS:
        if hook in scripts:
            script_cmd = scripts[hook]
            scripts_found[hook] = script_cmd

            # Generic lifecycle script warning
            findings.append({
                "rule_id": "JS-LIFE-000",
                "severity": "MEDIUM",
                "title": f"Active npm Lifecycle Hook '{hook}'",
                "description": f"Package defines automated '{hook}' execution hook: '{script_cmd}'",
                "mitre_id": "T1059.007"
            })

            # Check specific dangerous CLI patterns in lifecycle scripts
            for pattern, rule_id, severity, title, mitre in DANGEROUS_CLI_PATTERNS:
                if re.search(pattern, script_cmd, re.IGNORECASE):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "title": title,
                        "description": f"Lifecycle script '{hook}' contains malicious payload pattern: '{script_cmd}'",
                        "mitre_id": mitre
                    })

    # Risk score calculation for npm manifest
    risk_score = 0
    for f in findings:
        sev = f.get("severity")
        if sev == "CRITICAL":
            risk_score += 40
        elif sev == "HIGH":
            risk_score += 25
        elif sev == "MEDIUM":
            risk_score += 10

    risk_score = min(100, risk_score)
    verdict = "CLEAN" if risk_score == 0 else ("SUSPICIOUS" if risk_score < 70 else "CRITICAL_MALICIOUS")

    return {
        "success": True,
        "package_name": package_name,
        "version": version,
        "scripts_found": scripts_found,
        "findings": findings,
        "risk_score": risk_score,
        "verdict": verdict
    }


def analyze_javascript_code(js_code: str, filename: str = "script.js") -> Dict[str, Any]:
    """Scans JavaScript source code using regex taint patterns for dangerous calls."""
    findings: List[Dict[str, Any]] = []

    for pattern, rule_id, severity, title, mitre in JS_CODE_PATTERNS:
        matches = re.finditer(pattern, js_code, re.IGNORECASE)
        for m in matches:
            matched_text = m.group(0)
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": f"Detected suspicious JS call '{matched_text}' in {filename}",
                "snippet": matched_text,
                "mitre_id": mitre
            })

    # Compute risk score
    risk_score = 0
    for f in findings:
        sev = f.get("severity")
        if sev == "CRITICAL":
            risk_score += 35
        elif sev == "HIGH":
            risk_score += 20
        elif sev == "MEDIUM":
            risk_score += 10

    risk_score = min(100, risk_score)
    verdict = "CLEAN" if risk_score == 0 else ("SUSPICIOUS" if risk_score < 70 else "CRITICAL_MALICIOUS")

    return {
        "success": True,
        "filename": filename,
        "findings": findings,
        "risk_score": risk_score,
        "verdict": verdict
    }
