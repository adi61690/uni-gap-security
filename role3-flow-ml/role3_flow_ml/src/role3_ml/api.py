from __future__ import annotations
import os, asyncio, json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from .schemas import FlowFeatures
from .detector import Detector
from .training import train
from .models import Role3Models
app=FastAPI(title='Uni-Gap Role 3 Flow & Statistical Anomaly ML',version='2.0.0')
MODEL_DIR=os.getenv('ROLE3_MODEL_DIR','models')
model_path=Path(MODEL_DIR)
if not model_path.exists() or not (model_path/'xgb_multiclass.joblib').exists():
    fallback='models'
    MODEL_DIR=fallback
det=Detector(Role3Models(MODEL_DIR))
clients:set[WebSocket]=set()

@app.get('/health')
def health(): return {'status':'ok','service':'role3_ml','version':'2.0.0','model_loaded':det.models.classifier is not None}
@app.post('/train')
def train_models():
    global det; train(MODEL_DIR); det=Detector(Role3Models(MODEL_DIR)); return {'status':'trained','model_dir':MODEL_DIR}
@app.post('/predict')
def predict(feature: FlowFeatures): return det.predict(feature)
@app.post('/ingest')
async def ingest(feature: FlowFeatures):
    result=det.predict(feature)
    if result.get('is_alert'):
        dead=[]
        for ws in list(clients):
            try: await ws.send_json(result['alert'])
            except Exception: dead.append(ws)
        for ws in dead: clients.discard(ws)
    return result
@app.websocket('/ws/detections')
async def ws_detections(ws:WebSocket):
    await ws.accept(); clients.add(ws)
    try:
        while True:
            msg=await ws.receive_text()
            if msg=='ping': await ws.send_json({'type':'pong'})
            elif msg.startswith('{'):
                try:
                    result=det.predict(FlowFeatures.model_validate(json.loads(msg)))
                    if result.get('is_alert'): await ws.send_json(result['alert'])
                    else: await ws.send_json({'type':'observation',**result['observation']})
                except Exception as e: await ws.send_json({'type':'error','message':str(e)})
    except WebSocketDisconnect: clients.discard(ws)
