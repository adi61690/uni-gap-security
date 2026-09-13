from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import AlertRecord, User, AuditEvent
from ..security import current_user
from ..services.ml import health as ml_health
from ..config import get_settings

router=APIRouter(prefix="/api/v1",tags=["system"])

@router.get("/health")
def health(db:Session=Depends(get_db)):
    s=get_settings(); return {"status":"ok","service":"uni-gap-backend","demo_mode":s.demo_stream_enabled,"security":{"read_only":True,"one_way":True,"metadata_only":True,"active_probing":False,"inline_mitigation":False,"payload_decryption":False},"ml":ml_health()}

@router.get("/diode")
def diode(user:User=Depends(current_user)):
    return {"status":"ACTIVE","one_way":True,"read_only":True,"return_path":False,"active_probing":False,"inline_mitigation":False,"payload_decryption":False,"ingest_rate_mbps":None,"dropped_packets":None,"integrity":"OBSERVATION_ONLY","uptime_seconds":None}

@router.get("/network/summary")
def network_summary(db:Session=Depends(get_db),user:User=Depends(current_user)):
    protocols={r[0]:r[1] for r in db.execute(select(AlertRecord.protocol,func.count()).group_by(AlertRecord.protocol)).all()}
    dest={r[0]:r[1] for r in db.execute(select(AlertRecord.destination_ip,func.count()).group_by(AlertRecord.destination_ip)).all()}
    src={r[0]:r[1] for r in db.execute(select(AlertRecord.source_ip,func.count()).group_by(AlertRecord.source_ip)).all()}
    ports={str(r[0]):r[1] for r in db.execute(select(AlertRecord.destination_port,func.count()).group_by(AlertRecord.destination_port)).all()}
    return {"direction":"observed ingress only","protocols":protocols,"top_destinations":dest,"top_sources":src,"destination_ports":ports,"active_actions":[]}
