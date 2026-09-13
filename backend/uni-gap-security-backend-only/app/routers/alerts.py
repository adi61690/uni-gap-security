from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import AlertRecord, User
from ..schemas import PredictRequest
from ..security import current_user
from ..services.ml import predict
from ..services.ws import manager
from ..services.audit import record

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

@router.get("")
def list_alerts(q: str|None=None, threat_class: str|None=None, severity: str|None=None, min_confidence: float|None=None, limit: int=100, offset: int=0, db: Session=Depends(get_db), user: User=Depends(current_user)):
    stmt = select(AlertRecord).order_by(AlertRecord.timestamp.desc())
    cond=[]
    if q:
        like=f"%{q}%"; cond.append(or_(AlertRecord.flow_id.like(like), AlertRecord.source_ip.like(like), AlertRecord.destination_ip.like(like), AlertRecord.threat_class.like(like), AlertRecord.protocol.like(like)))
    if threat_class: cond.append(AlertRecord.threat_class==threat_class)
    if severity: cond.append(AlertRecord.severity==severity)
    if min_confidence is not None: cond.append(AlertRecord.confidence >= min_confidence)
    if cond: stmt=stmt.where(*cond)
    rows=list(db.scalars(stmt.offset(offset).limit(min(limit,500))))
    return {"items":[r.payload for r in rows],"count":len(rows)}

@router.post("/predict")
async def predict_and_broadcast(req: PredictRequest, db: Session=Depends(get_db), user: User=Depends(current_user)):
    result = predict(req.model_dump())
    if hasattr(result, "model_dump"):
        result = result.model_dump()
    if result.get("is_alert") and result.get("alert"):
        a=result["alert"]; _save_alert(db,a); await manager.broadcast({"type":"alert", **a})
    return result

@router.get("/stats")
def stats(db: Session=Depends(get_db), user: User=Depends(current_user)):
    total=db.scalar(select(func.count(AlertRecord.id))) or 0
    critical=db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.severity=="Critical")) or 0
    avg=db.scalar(select(func.avg(AlertRecord.confidence))) or 0
    classes={r[0]:r[1] for r in db.execute(select(AlertRecord.threat_class, func.count()).group_by(AlertRecord.threat_class)).all()}
    return {"total":total,"critical":critical,"average_confidence":float(avg),"distribution":classes}

def _save_alert(db, a):
    try: ts=datetime.fromisoformat(a["timestamp"].replace("Z","+00:00"))
    except Exception: ts=datetime.now(timezone.utc)
    row=AlertRecord(timestamp=ts,flow_id=a["flow_id"],threat_class=a["threat_class"],threat_subtype=a["threat_subtype"],severity=a["severity"],confidence=a["confidence"],source_ip=a["source_ip"],destination_ip=a["destination_ip"],destination_port=a["destination_port"],protocol=a["protocol"],payload=a)
    db.add(row); db.commit(); db.refresh(row); return row

async def websocket_handler(ws: WebSocket):
    await manager.connect(ws)
    await ws.send_json({"type":"connected","service":"uni-gap-backend","demo_stream":True})
    try:
        while True:
            raw=await ws.receive_text()
            if raw.lower().strip()=="ping": await ws.send_json({"type":"pong"}); continue
            import json
            payload=json.loads(raw)
            result=predict(payload)
            if hasattr(result, "model_dump"):
                result = result.model_dump()
            await ws.send_json({"type":"prediction", **result})
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception as exc:
        await manager.disconnect(ws)
        try: await ws.send_json({"type":"error","message":"Invalid event"})
        except Exception: pass
