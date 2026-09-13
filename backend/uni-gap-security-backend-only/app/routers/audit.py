from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import select, or_
from sqlalchemy.orm import Session
import csv, io
from ..db import get_db
from ..models import AuditEvent, User
from ..security import current_user

router=APIRouter(prefix="/api/v1/audit",tags=["audit"])

@router.get("")
def list_audit(q:str|None=None, event:str|None=None, limit:int=200, db:Session=Depends(get_db), user:User=Depends(current_user)):
    stmt=select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(min(limit,500))
    if q:
        s=f"%{q}%"; stmt=stmt.where(or_(AuditEvent.analyst.like(s),AuditEvent.event.like(s),AuditEvent.session_id.like(s)))
    if event: stmt=stmt.where(AuditEvent.event==event)
    rows=list(db.scalars(stmt))
    return [{"timestamp":r.timestamp.isoformat(),"analyst":r.analyst,"role":r.role,"event":r.event,"status":r.status,"session":r.session_id,"details":r.details} for r in rows]

@router.get("/export.csv")
def export_audit(db:Session=Depends(get_db), user:User=Depends(current_user)):
    out=io.StringIO(); w=csv.writer(out); w.writerow(["timestamp","analyst","role","event","status","session"])
    for r in db.scalars(select(AuditEvent).order_by(AuditEvent.timestamp.desc())): w.writerow([r.timestamp.isoformat(),r.analyst,r.role,r.event,r.status,r.session_id or ""])
    out.seek(0); return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=audit.csv"})
