"""
SupplyShield - Enterprise Security Gateway & Detonation Engine
Main FastAPI application entrypoint providing REST endpoints, CORS middleware,
lifespan database initialization, and real-time WebSocket telemetry.
"""

import os
import sys
from contextlib import asynccontextmanager
import logging

# Ensure backend root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import init_db
from api.routes_scan import router as scan_router
from api.websocket_feed import ws_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("supplyshield.gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Executes startup initialization (DB schemas) and handles clean shutdown.
    """
    logger.info("[*] Initializing SupplyShield Security Gateway & Detonation Engine...")
    init_db()
    logger.info("[+] SQLite audit ledger initialized and ready.")
    yield
    logger.info("[-] SupplyShield Gateway shutting down. Disconnecting active clients...")
    for ws in list(ws_manager.active_connections):
        try:
            await ws.close()
        except Exception:
            pass


app = FastAPI(
    title="SupplyShield Security Gateway & Detonation Engine",
    description=(
        "Autonomous Software Supply-Chain Malicious Package Detonation Sandbox "
        "and AST Taint Analysis Engine API."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure Cross-Origin Resource Sharing (CORS) for frontend client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local dev and SOC dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Routes
app.include_router(scan_router, prefix="/api")


# --- WebSocket Telemetry Route ---

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint that streams continuous SOC detonation telemetry,
    AST analysis events, canary alerts, and risk assessments to the frontend.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep the socket open and receive heartbeat or ping from frontend
            data = await websocket.receive_text()
            # Send immediate ACK back to client
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


# --- Root Route ---

@app.get("/", tags=["General"])
async def root():
    """Root endpoint verifying gateway uptime and API documentation access."""
    return {
        "service": "SupplyShield Security Gateway",
        "status": "ONLINE",
        "version": "1.0.0",
        "docs_url": "/docs",
        "websocket_url": "/ws/telemetry",
        "endpoints": [
            "POST /api/scan/code",
            "POST /api/scan/package",
            "GET /api/history",
            "GET /api/scan/{scan_id}",
            "GET /api/health"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.API_HOST, port=settings.API_PORT, reload=True)
