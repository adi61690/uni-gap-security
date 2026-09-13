from fastapi import APIRouter, Depends
from sqlalchemy import select, or_
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import AlertRecord, User
from ..schemas import HuntRequest
from ..security import current_user

router=APIRouter(prefix="/api/v1/hunt", tags=["threat-hunt"])

@router.post("/search")
def search(req:HuntRequest, db:Session=Depends(get_db), user:User=Depends(current_user)):
    stmt=select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(200)
    if req.q:
        q=f"%{req.q}%"; stmt=stmt.where(or_(AlertRecord.flow_id.like(q),AlertRecord.source_ip.like(q),AlertRecord.destination_ip.like(q),AlertRecord.protocol.like(q),AlertRecord.payload.cast(str).like(q)))
    if req.threat_class: stmt=stmt.where(AlertRecord.threat_class==req.threat_class)
    if req.protocol: stmt=stmt.where(AlertRecord.protocol==req.protocol)
    stmt=stmt.where(AlertRecord.confidence>=req.min_confidence)
    return {"items":[r.payload for r in db.scalars(stmt)]}
