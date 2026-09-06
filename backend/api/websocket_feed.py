"""
SupplyShield - Real-Time WebSocket Telemetry Feed
Broadcasts live security telemetry, execution logs, and detonation progress to active frontend clients.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import WebSocket

logger = logging.getLogger("supplyshield.websocket")


class TelemetryConnectionManager:
    """
    Manages active WebSocket connections and broadcasts structured real-time
    telemetry events during static AST parsing and dynamic sandbox detonation.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")
        # Send welcome handshake event
        await self.send_to_client(websocket, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": "HANDSHAKE",
            "level": "INFO",
            "message": "SupplyShield SOC Telemetry Pipeline Connected.",
            "payload": {"active_nodes": len(self.active_connections)}
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def send_to_client(self, websocket: WebSocket, data: Dict[str, Any]):
        try:
            await websocket.send_json(data)
        except Exception as e:
            logger.warning(f"Failed to send telemetry to client: {e}")

    async def broadcast(self, data: Dict[str, Any]):
        """Broadcast an arbitrary payload to all currently connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception as e:
                logger.warning(f"Error broadcasting to client, marking for cleanup: {e}")
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    async def send_telemetry(
        self,
        stage: str,
        level: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None
    ):
        """
        Emits a standard structured telemetry log event across the broadcast channel.
        Stages: INITIALIZE | AST_STATIC | SANDBOX_DYNAMIC | RISK_SCORING | AUDIT_STORE | COMPLETE
        Levels: INFO | WARN | CRITICAL | SUCCESS | DEBUG
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "level": level.upper(),
            "message": message,
            "payload": payload or {}
        }
        await self.broadcast(event)


# Global singleton instance for use across API routes
ws_manager = TelemetryConnectionManager()
