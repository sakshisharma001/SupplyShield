"""
SupplyShield - SQLite Database & Audit Log Persistence
Manages persistent storage for all package scans, security assessments, and telemetry logs.
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "supplyshield_audit.db")

def get_db_connection() -> sqlite3.Connection:
    """Returns a connection to the SQLite audit database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema for scan history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL,
            composite_risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            severity_badge TEXT NOT NULL,
            slsa_level TEXT NOT NULL,
            total_findings INTEGER NOT NULL,
            execution_duration_sec REAL NOT NULL,
            report_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan_report(report: Dict[str, Any]) -> int:
    """Saves a completed security assessment report to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    package_name = report.get("package_name", "unnamed_package")
    score = report.get("composite_risk_score", 0)
    verdict = report.get("verdict", "UNKNOWN")
    severity = report.get("severity_badge", "INFO")
    slsa = report.get("slsa_security_level", "SLSA-Level-0")
    total_findings = report.get("total_findings_count", 0)
    duration = report.get("sandbox_telemetry", {}).get("execution_duration_sec", 0.0)
    report_json_str = json.dumps(report)
    
    cursor.execute("""
        INSERT INTO scan_history (
            package_name, scan_timestamp, composite_risk_score, verdict,
            severity_badge, slsa_level, total_findings, execution_duration_sec, report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        package_name, timestamp, score, verdict,
        severity, slsa, total_findings, duration, report_json_str
    ))
    
    inserted_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return inserted_id

def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves the most recent scan records for the dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, package_name, scan_timestamp, composite_risk_score,
               verdict, severity_badge, slsa_level, total_findings, execution_duration_sec
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves the complete report JSON for a specific scan ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT report_json FROM scan_history WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["report_json"])
    return None

# Auto-initialize database tables on module load
init_db()
