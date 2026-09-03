"""
SupplyShield - Configuration & Security Policies
Defines risk weights, sandbox execution limits, and heuristic signatures.
"""
from typing import List
from pydantic import BaseModel

class Settings(BaseModel):
    APP_NAME: str = "SupplyShield"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Gateway API Config
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ]
    
    # Ephemeral Sandbox Execution Limits
    SANDBOX_TIMEOUT_SECONDS: float = 3.0       # Hard kill after 3 seconds
    MAX_MEMORY_MB: int = 128                  # Max memory limit per execution
    TEMP_DIR_PREFIX: str = "supplyshield_env_"
    
    # Dangerous Function Signatures (AST Visitor)
    DANGEROUS_FUNCTIONS: List[str] = [
        "eval", "exec", "compile", "__import__",
        "os.system", "os.popen", "os.spawn",
        "subprocess.Popen", "subprocess.run", "subprocess.call",
        "shutil.rmtree", "pty.spawn"
    ]
    
    # Sensitive Target Files (Filesystem Watchdog / Canary)
    SENSITIVE_TARGET_FILES: List[str] = [
        ".ssh/id_rsa", ".ssh/id_ed25519",
        ".env", ".aws/credentials",
        ".config/gcloud", "passwd", "shadow"
    ]
    
    # Risk Scoring Thresholds
    RISK_THRESHOLD_SAFE: int = 29
    RISK_THRESHOLD_SUSPICIOUS: int = 69
    RISK_THRESHOLD_CRITICAL: int = 70

settings = Settings()
