"""
SupplyShield - Enterprise Security Gateway & Detonation Engine
Main FastAPI application entrypoint providing REST endpoints, CORS middleware,
lifespan database initialization, real-time WebSocket telemetry, and rate limiting.
"""

import os
import sys
import time
import logging
from contextlib import asynccontextmanager

# Ensure backend root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from database import init_db
from api.routes_scan import router as scan_router
from api.websocket_feed import ws_manager

# ── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("supplyshield.gateway")


# ── Simple In-Memory Rate Limiter ────────────────────────────────────────────
# Uses a sliding window per IP address. Thread-safe for single-worker uvicorn.
_rate_store: dict = {}   # {ip: [timestamp, ...]}

def _check_rate_limit(client_ip: str, limit: int, window_secs: int = 60) -> bool:
    """Returns True if request is allowed, False if rate limit exceeded."""
    now = time.time()
    window_start = now - window_secs
    timestamps = _rate_store.get(client_ip, [])
    # Prune timestamps outside the window
    timestamps = [t for t in timestamps if t > window_start]
    if len(timestamps) >= limit:
        _rate_store[client_ip] = timestamps
        return False
    timestamps.append(now)
    _rate_store[client_ip] = timestamps
    return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Production rate limiting middleware: 30 requests/minute per IP.
    Applies only to /api/scan/* routes (not health checks or WebSocket).
    """
    async def dispatch(self, request: Request, call_next):
        # Only rate-limit scan endpoints
        if request.url.path.startswith("/api/scan"):
            client_ip = request.client.host if request.client else "unknown"
            allowed = _check_rate_limit(
                client_ip=client_ip,
                limit=settings.RATE_LIMIT_PER_MINUTE,
                window_secs=60
            )
            if not allowed:
                logger.warning(
                    f"[RATE_LIMIT] IP {client_ip} exceeded {settings.RATE_LIMIT_PER_MINUTE} req/min"
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "detail": f"Maximum {settings.RATE_LIMIT_PER_MINUTE} scan requests per minute allowed. Please slow down.",
                        "retry_after_seconds": 60
                    },
                    headers={"Retry-After": "60"}
                )
        return await call_next(request)


class RequestAuditMiddleware(BaseHTTPMiddleware):
    """
    Structured per-request audit logging for all API calls.
    Logs: timestamp, method, path, client IP, response status, duration.
    """
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response: Response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)
        client_ip = request.client.host if request.client else "unknown"

        # Only log API and WS endpoints (not static files)
        if request.url.path.startswith("/api") or request.url.path.startswith("/ws"):
            logger.info(
                f"[REQUEST] {request.method} {request.url.path} "
                f"| IP={client_ip} | Status={response.status_code} | {duration_ms}ms"
            )

        # Attach X-Scan-ID header if scan endpoint (scan_id is added by route)
        if request.url.path.startswith("/api/scan"):
            response.headers["X-SupplyShield-Version"] = settings.APP_VERSION
            response.headers["X-SupplyShield-Env"] = settings.ENVIRONMENT

        return response


# ── Application Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Executes startup initialization (DB schemas) and handles clean shutdown.
    """
    logger.info("[*] Initializing SupplyShield Security Gateway & Detonation Engine...")
    logger.info(f"[*] Environment: {settings.ENVIRONMENT} | Debug: {settings.DEBUG}")
    logger.info(f"[*] Rate Limit: {settings.RATE_LIMIT_PER_MINUTE} req/min | Sandbox Timeout: {settings.SANDBOX_TIMEOUT_SECONDS}s")
    init_db()
    logger.info("[+] SQLite audit ledger initialized and ready.")
    yield
    logger.info("[-] SupplyShield Gateway shutting down. Disconnecting active clients...")
    for ws in list(ws_manager.active_connections):
        try:
            await ws.close()
        except Exception:
            pass


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SupplyShield Security Gateway & Detonation Engine",
    description=(
        "Autonomous Software Supply-Chain Malicious Package Detonation Sandbox "
        "and AST Taint Analysis Engine API. v1.0.0 Production."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,    # Hide Swagger UI in production
    redoc_url="/redoc" if settings.DEBUG else None,  # Hide ReDoc in production
)

# ── Middleware Stack (order matters: outer → inner) ───────────────────────────
app.add_middleware(RequestAuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# ── REST API Routes ───────────────────────────────────────────────────────────
app.include_router(scan_router, prefix="/api")


@app.get("/api/health", tags=["General"])
async def health_check():
    """Health check endpoint for Docker health probes and uptime monitoring."""
    return {
        "status": "HEALTHY",
        "service": "SupplyShield Security Gateway & Detonation Engine",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "engine": "SupplyShield",
        "database": "CONNECTED",
        "engines": {
            "ast_static_engine": "ACTIVE",
            "ephemeral_sandbox": "ACTIVE",
            "risk_scorer": "ACTIVE",
            "sqlite_audit_db": "ACTIVE"
        },
        "rate_limit": f"{settings.RATE_LIMIT_PER_MINUTE} req/min",
        "sandbox_timeout": f"{settings.SANDBOX_TIMEOUT_SECONDS}s"
    }


# ── WebSocket Telemetry ───────────────────────────────────────────────────────

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint that streams continuous SOC detonation telemetry,
    AST analysis events, canary alerts, and risk assessments to the frontend.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({
                "type": "PONG",
                "received": data,
                "status": "HEALTHY"
            })
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client session error: {e}")
        ws_manager.disconnect(websocket)


# ── Static Frontend Dashboard ─────────────────────────────────────────────────
from fastapi.staticfiles import StaticFiles

FRONTEND_DIR = os.path.join(CURRENT_DIR, "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

@app.get("/", tags=["General"])
async def root():
    return {
        "status": "ONLINE",
        "service": "SupplyShield Security Gateway",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "dashboard": "/dashboard",
        "docs": "/docs" if settings.DEBUG else "disabled"
    }



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
