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


@app.get("/api/health", tags=["General"])
async def health_check():
    """Health check endpoint for Docker health probes and uptime monitoring."""
    return {
        "status": "HEALTHY",
        "service": "SupplyShield Security Gateway & Detonation Engine",
        "version": "1.0.0",
        "engine": "SupplyShield",
        "database": "CONNECTED"
    }


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


from fastapi.staticfiles import StaticFiles

# --- Static Frontend Dashboard Mounting ---
FRONTEND_DIR = os.path.join(CURRENT_DIR, "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    # Also mount at root for instant access if HTML file exists
    @app.get("/api/info", tags=["General"])
    async def api_info():
        return {
            "service": "SupplyShield Security Gateway",
            "status": "ONLINE",
            "version": "1.0.0",
            "docs_url": "/docs",
            "websocket_url": "/ws/telemetry"
        }
    
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="root_frontend")
else:
    @app.get("/", tags=["General"])
    async def root():
        return {
            "service": "SupplyShield Security Gateway",
            "status": "ONLINE",
            "version": "1.0.0"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
