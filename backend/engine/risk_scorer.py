"""
SupplyShield - Multi-Vector Risk Engine & MITRE ATT&CK Classifier
Combines Static AST findings and Dynamic Sandbox telemetry to compute:
- Composite Weighted Risk Score (0 to 100)
- Threat Verdict (CLEAN, SUSPICIOUS, CRITICAL_MALICIOUS)
- International MITRE ATT&CK TTP taxonomy classifications
- Executive remediation advice & SLSA supply-chain posture
"""

from typing import Dict, List, Any
from config import settings

# Global MITRE ATT&CK Tactic Categories
MITRE_TACTIC_MAP = {
    "T1059": {"tactic": "Execution", "name": "Command and Scripting Interpreter"},
    "T1059.006": {"tactic": "Execution", "name": "Python Command Execution"},
    "T1027": {"tactic": "Defense Evasion", "name": "Obfuscated / Encrypted Information"},
    "T1036": {"tactic": "Defense Evasion", "name": "Masquerading (Trojan Source)"},
    "T1552": {"tactic": "Credential Access", "name": "Credentials in Files (.env / .aws)"},
    "T1552.004": {"tactic": "Credential Access", "name": "Private Keys (.ssh/id_rsa)"},
    "T1071": {"tactic": "Command and Control", "name": "Application Layer Protocol"},
    "T1499": {"tactic": "Impact", "name": "Endpoint Denial of Service / Persistent Loop"}
}

class RiskScoringEngine:
    """
    Evaluates multi-stage evidence across AST and Sandbox engines to compute
    statistically robust security scores with correlation boosts.
    """

    def compute_assessment(
        self,
        package_name: str,
        ast_result: Dict[str, Any],
        sandbox_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Synthesizes AST and Dynamic results into a single unified security assessment.
        """
        static_score = ast_result.get("static_risk_score", 0)
        dynamic_score = sandbox_result.get("dynamic_risk_score", 0)
        
        static_findings = ast_result.get("findings", [])
        dynamic_findings = sandbox_result.get("dynamic_findings", [])
        
        # 1. Base Weighted Score (40% Static AST + 60% Dynamic Sandbox)
        base_score = (static_score * 0.4) + (dynamic_score * 0.6)
        
        # 2. Correlation Multiplier (Multi-Stage Exploit Detection)
        # If static detected obfuscation AND dynamic detected credential/network access -> Exploit Chain Confirmed!
        correlation_flags = []
        correlation_bonus = 0
        
        has_static_obfuscation = any(f.get("rule_id") in ["SEC-OBF-004", "SEC-DYN-001", "SEC-BIDI-000"] for f in static_findings)
        has_dynamic_canary = any(f.get("rule_id") in ["DYN-CANARY-001", "DYN-CANARY-002", "DYN-CANARY-003"] for f in dynamic_findings)
        has_dynamic_timeout = sandbox_result.get("status") == "TIMEOUT_KILLED"
        has_dynamic_network = any(f.get("rule_id") == "DYN-NET-002" for f in dynamic_findings)
        
        if has_static_obfuscation and has_dynamic_canary:
            correlation_bonus += 35
            correlation_flags.append("CONFIRMED_MULTI_STAGE_CREDENTIAL_HARVESTER")
            
        if has_static_obfuscation and (has_dynamic_timeout or has_dynamic_network):
            correlation_bonus += 30
            correlation_flags.append("CONFIRMED_OBFUSCATED_REVERSE_SHELL")

        final_composite_score = min(int(round(base_score + correlation_bonus)), 100)
        
        # 3. Determine Final Security Verdict
        if final_composite_score <= settings.RISK_THRESHOLD_SAFE:
            verdict = "CLEAN"
            severity_badge = "LOW_RISK"
            action = "ALLOW_INSTALLATION"
            summary_message = "Package exhibits standard legitimate behavior. No malicious vectors or data exfiltration detected."
        elif final_composite_score <= settings.RISK_THRESHOLD_SUSPICIOUS:
            verdict = "SUSPICIOUS"
            severity_badge = "MEDIUM_RISK"
            action = "MANUAL_REVIEW_RECOMMENDED"
            summary_message = "Package contains suspicious patterns (e.g. dynamic imports or complex encoding). Manual audit advised before production deployment."
        else:
            verdict = "CRITICAL_MALICIOUS"
            severity_badge = "CRITICAL_THREAT"
            action = "BLOCK_AND_ISOLATE"
            summary_message = "CRITICAL SECURITY BREACH: Package contains confirmed malicious supply-chain vectors (Credential theft, obfuscated execution, or reverse shell)."

        # 4. Map and Aggregate All MITRE ATT&CK TTPs
        mitre_tactics = self._aggregate_mitre_ttps(static_findings + dynamic_findings)
        
        # 5. Determine SLSA Supply Chain Assurance Tier
        slsa_level = self._compute_slsa_level(final_composite_score, static_findings, dynamic_findings)

        return {
            "package_name": package_name,
            "verdict": verdict,
            "severity_badge": severity_badge,
            "recommended_action": action,
            "composite_risk_score": final_composite_score,
            "score_breakdown": {
                "static_ast_score": static_score,
                "dynamic_sandbox_score": dynamic_score,
                "correlation_bonus": correlation_bonus,
                "correlation_flags": correlation_flags
            },
            "summary": summary_message,
            "mitre_attack_matrix": mitre_tactics,
            "slsa_security_level": slsa_level,
            "total_findings_count": len(static_findings) + len(dynamic_findings),
            "static_findings": static_findings,
            "dynamic_findings": dynamic_findings,
            "sandbox_telemetry": {
                "status": sandbox_result.get("status"),
                "execution_duration_sec": sandbox_result.get("execution_duration_sec", 0),
                "stdout": sandbox_result.get("stdout", ""),
                "stderr": sandbox_result.get("stderr", "")
            }
        }

    def _aggregate_mitre_ttps(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregates MITRE ATT&CK techniques with descriptions and tactics."""
        seen_techniques = set()
        ttps = []
        
        for f in all_findings:
            mitre_tag = f.get("mitre_tag", "")
            if not mitre_tag:
                continue
                
            tech_id = mitre_tag.split()[0]
            if tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                info = MITRE_TACTIC_MAP.get(tech_id, {"tactic": "General", "name": mitre_tag})
                ttps.append({
                    "technique_id": tech_id,
                    "tactic": info["tactic"],
                    "technique_name": info["name"],
                    "severity": f.get("severity", "MEDIUM")
                })
        return ttps

    def _compute_slsa_level(self, score: int, static_findings: list, dynamic_findings: list) -> str:
        """Computes Software Supply Chain (SLSA) compliance readiness level."""
        if score == 0:
            return "SLSA-Level-4 (Fully Verified & Hardened)"
        elif score < 30:
            return "SLSA-Level-3 (Standard Verification Passed)"
        elif score < 70:
            return "SLSA-Level-1 (Unverified Third-Party Risks)"
        return "SLSA-Level-0 (Compromised / Hostile Dependency)"

# Global Risk Engine Instance
risk_engine = RiskScoringEngine()
