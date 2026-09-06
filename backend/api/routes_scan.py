"""
SupplyShield - REST API Endpoints for Security Scanning & Telemetry
Provides endpoints for synchronous code analysis, package file uploads,
scan history retrieval, and detailed report inspection.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel, Field

from engine.ast_analyzer import analyze_source_ast
from engine.sandbox import DynamicSandbox
from engine.risk_scorer import RiskScoringEngine
from database import save_scan_report, get_recent_scans, get_scan_by_id
from api.websocket_feed import ws_manager

router = APIRouter(tags=["Security Scanning"])

# Single shared instances of detection engines
sandbox_engine = DynamicSandbox()
scorer_engine = RiskScoringEngine()


# --- Pydantic Request & Response Schemas ---

class ScanCodeRequest(BaseModel):
    code: str = Field(..., description="Python source code to detonate and analyze", min_length=1)
    package_name: Optional[str] = Field("submitted_package.py", description="Target package or filename identifier")


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    engines: Dict[str, str]


# --- Core Analysis Pipeline Function ---

async def execute_security_pipeline(source_code: str, package_name: str) -> Dict[str, Any]:
    """
    Executes the full 3-Stage SupplyShield Security Scanning Pipeline:
    1. Static AST Parsing & Entropy / Bidi Checks
    2. Isolated Dynamic Detonation in Subprocess Sandbox
    3. Composite Multi-Vector Risk Scoring & MITRE ATT&CK Mapping
    Broadcasts real-time SOC logs via WebSocket at each step.
    """
    # Telemetry: Start
    await ws_manager.send_telemetry(
        stage="INITIALIZE",
        level="INFO",
        message=f"Starting multi-vector security scan for '{package_name}' ({len(source_code.splitlines())} lines)...",
        payload={"package_name": package_name, "char_count": len(source_code)}
    )

    # 1. AST Static Analysis
    await ws_manager.send_telemetry(
        stage="AST_STATIC",
        level="INFO",
        message="Stage 1/3: Parsing Abstract Syntax Tree (AST) & computing Shannon entropy...",
        payload={"stage": "AST_STATIC"}
    )
    ast_result = analyze_source_ast(source_code)
    
    # Broadcast static findings
    for finding in ast_result.get("findings", []):
        level = "CRITICAL" if finding.get("severity") == "CRITICAL" else "WARN"
        await ws_manager.send_telemetry(
            stage="AST_STATIC",
            level=level,
            message=f"AST [{finding.get('rule_id')}]: {finding.get('title')}",
            payload=finding
        )

    # 2. Dynamic Sandbox Detonation
    await ws_manager.send_telemetry(
        stage="SANDBOX_DYNAMIC",
        level="INFO",
        message="Stage 2/3: Deploying isolated ephemeral sandbox & synthetic canary tripwires...",
        payload={"stage": "SANDBOX_DYNAMIC"}
    )
    sandbox_result = sandbox_engine.detonate(source_code=source_code, package_name=package_name)

    # Broadcast dynamic findings
    for dyn_finding in sandbox_result.get("dynamic_findings", []):
        await ws_manager.send_telemetry(
            stage="SANDBOX_DYNAMIC",
            level="CRITICAL",
            message=f"Sandbox Alert [{dyn_finding.get('rule_id')}]: {dyn_finding.get('title')}",
            payload=dyn_finding
        )

    if sandbox_result.get("status") == "TIMEOUT_KILLED":
        await ws_manager.send_telemetry(
            stage="SANDBOX_DYNAMIC",
            level="CRITICAL",
            message="Sandbox Watchdog: Execution exceeded 3.0s threshold. Hard SIGKILL dispatched!",
            payload={"exit_code": sandbox_result.get("exit_code")}
        )

    # 3. Composite Risk Scoring & MITRE ATT&CK Mapping
    await ws_manager.send_telemetry(
        stage="RISK_SCORING",
        level="INFO",
        message="Stage 3/3: Synthesizing multi-vector telemetry & calculating composite risk score...",
        payload={"stage": "RISK_SCORING"}
    )
    assessment = scorer_engine.compute_assessment(
        package_name=package_name,
        ast_result=ast_result,
        sandbox_result=sandbox_result
    )

    # 4. Audit Log Persistence
    await ws_manager.send_telemetry(
        stage="AUDIT_STORE",
        level="INFO",
        message="Archiving cryptographic security assessment into SQLite audit database...",
        payload={"package_name": package_name}
    )
    scan_id = save_scan_report(assessment)
    assessment["scan_id"] = scan_id

    # 5. Final Completed Telemetry
    final_level = "SUCCESS" if assessment.get("verdict") == "CLEAN" else "CRITICAL"
    await ws_manager.send_telemetry(
        stage="COMPLETE",
        level=final_level,
        message=f"Scan complete. Verdict: {assessment.get('verdict')} | Score: {assessment.get('composite_risk_score')}/100 | SLSA: {assessment.get('slsa_security_level')}",
        payload={
            "scan_id": scan_id,
            "score": assessment.get("composite_risk_score"),
            "verdict": assessment.get("verdict"),
            "slsa": assessment.get("slsa_security_level")
        }
    )

    return assessment


# --- API Routes ---

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Healthcheck endpoint reporting active detection subsystems and server state."""
    return {
        "status": "HEALTHY",
        "service": "SupplyShield Detonation Engine",
        "version": "1.0.0",
        "engines": {
            "ast_static_engine": "ACTIVE",
            "ephemeral_sandbox": "ACTIVE",
            "risk_scorer": "ACTIVE",
            "sqlite_audit_db": "ACTIVE",
            "websocket_telemetry": f"ACTIVE ({len(ws_manager.active_connections)} clients)"
        }
    }


@router.post("/scan/code")
async def scan_raw_code(request: ScanCodeRequest):
    """
    Directly scans raw Python source code through AST analysis, dynamic detonation,
    and composite risk scoring.
    """
    try:
        report = await execute_security_pipeline(
            source_code=request.code,
            package_name=request.package_name or "code_snippet.py"
        )
        return {
            "success": True,
            "report": report
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scanning failed: {str(e)}"
        )


@router.post("/scan/package")
async def scan_package_file(
    file: UploadFile = File(..., description="Python script or package file to analyze (.py)"),
    package_name: Optional[str] = Form(None)
):
    """
    Accepts uploaded Python package files (.py), runs them through the full detonation
    sandbox, and returns the complete security assessment report.
    """
    try:
        content_bytes = await file.read()
        try:
            source_code = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            source_code = content_bytes.decode("latin-1", errors="ignore")

        target_name = package_name or file.filename or "uploaded_package.py"
        
        report = await execute_security_pipeline(
            source_code=source_code,
            package_name=target_name
        )
        return {
            "success": True,
            "filename": target_name,
            "file_size_bytes": len(content_bytes),
            "report": report
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Package file scan failed: {str(e)}"
        )


@router.get("/history")
async def fetch_scan_history(limit: int = 20):
    """
    Retrieves the most recent scan records from SQLite audit database for dashboard feeds.
    """
    try:
        scans = get_recent_scans(limit=limit)
        return {
            "success": True,
            "count": len(scans),
            "scans": scans
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch scan history: {str(e)}"
        )


@router.get("/scan/{scan_id}")
async def fetch_scan_details(scan_id: int):
    """
    Retrieves the complete JSON security audit report for a specific scan ID.
    """
    report = get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID {scan_id} not found."
        )
    return {
        "success": True,
        "scan_id": scan_id,
        "report": report
    }
