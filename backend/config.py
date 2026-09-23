"""
SupplyShield - Configuration & Security Policies
Reads environment variables for production deployments.
Run with: SUPPLYSHIELD_ENV=production to enable hardened mode.
"""
import os
from typing import List
from pydantic import BaseModel


def _env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return default


class Settings(BaseModel):
    APP_NAME: str = "SupplyShield"
    APP_VERSION: str = "1.0.0"

    # Read from env — defaults to 'production' for safety
    ENVIRONMENT: str = os.environ.get("SUPPLYSHIELD_ENV", "production")
    DEBUG: bool = _env_bool("SUPPLYSHIELD_DEBUG", False)

    # Gateway API Config
    HOST: str = os.environ.get("SUPPLYSHIELD_HOST", "127.0.0.1")
    PORT: int = int(os.environ.get("SUPPLYSHIELD_PORT", "8000"))

    # CORS — read from env (comma-separated), fallback to local dev
    CORS_ORIGINS: List[str] = [
        o.strip()
        for o in os.environ.get(
            "SUPPLYSHIELD_CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if o.strip()
    ]

    # Ephemeral Sandbox Execution Limits
    SANDBOX_TIMEOUT_SECONDS: float = float(
        os.environ.get("SUPPLYSHIELD_SANDBOX_TIMEOUT", "3.0")
    )
    MAX_MEMORY_MB: int = 128
    TEMP_DIR_PREFIX: str = "supplyshield_env_"

    # File Upload Limits
    MAX_UPLOAD_SIZE_BYTES: int = 524288   # 512 KB for Python files
    MAX_JSON_UPLOAD_SIZE_BYTES: int = 65536  # 64 KB for npm manifests
    ALLOWED_EXTENSIONS: List[str] = [".py", ".json", ".js"]

    # API Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(
        os.environ.get("SUPPLYSHIELD_RATE_LIMIT", "30")
    )

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
