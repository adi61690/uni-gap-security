from __future__ import annotations

import asyncio
import json
import os
import random
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .constants import MODEL_VERSION
from .detector import Role4Detector
from .schemas import PredictRequest, PredictResponse

app = FastAPI(title="Uni-Gap Role 4 ML API", version=MODEL_VERSION, description="Passive metadata-only detection for DGA/DNS tunneling, encrypted malware and beaconing.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
detector = Role4Detector(os.getenv("ROLE4_MODEL_DIR", None) or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models"))
clients: Set[WebSocket] = set()

@app.get("/health")
def health():
    return {"status": "ok", "service": "role4_ml", "model_version": MODEL_VERSION, "catboost_loaded": (detector.dns_model is not None and detector.encrypted_model is not None), "sequence_model_loaded": detector.sequence is not None, "security": {"read_only": True, "one_way": True, "metadata_only": True, "payload_decryption": False}}

@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    return detector.predict(req)

@app.post("/ingest", response_model=PredictResponse)
def ingest(req: PredictRequest):
    return detector.predict(req)

async def _broadcast(payload: dict):
    stale = []
    for ws in list(clients):
        try:
            await ws.send_json(payload)
        except Exception:
            stale.append(ws)
    for ws in stale:
        clients.discard(ws)

@app.on_event("startup")
async def startup():
    app.state.demo_task = None

@app.on_event("shutdown")
async def shutdown():
    return None

@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    await ws.send_json({"type": "connected", "service": "role4_ml", "model_version": MODEL_VERSION, "demo_stream": False, "data_source": "backend_ingest"})
    try:
        while True:
            raw = await ws.receive_text()
            if raw.strip().lower() == "ping":
                await ws.send_json({"type": "pong"})
                continue
            event = json.loads(raw)
            result = detector.predict(PredictRequest(**event))
            await ws.send_json(result.model_dump())
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception as exc:
        clients.discard(ws)
        try:
            await ws.send_json({"type": "error", "message": str(exc)})
            await ws.close()
        except Exception:
            pass
