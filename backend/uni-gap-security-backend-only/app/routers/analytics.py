from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import AlertRecord, User
from ..security import current_user

router=APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

@router.get("")
def analytics(window: str="24h", db: Session=Depends(get_db), user: User=Depends(current_user)):
    hours={"1h":1,"6h":6,"24h":24,"7d":168,"30d":720}.get(window,24)
    since=datetime.now(timezone.utc)-timedelta(hours=hours)
    rows=list(db.scalars(select(AlertRecord).where(AlertRecord.timestamp>=since).order_by(AlertRecord.timestamp)))
    by_class={}; by_severity={}; destinations={}; confidence=[]
    for a in rows:
        by_class[a.threat_class]=by_class.get(a.threat_class,0)+1; by_severity[a.severity]=by_severity.get(a.severity,0)+1; destinations[a.destination_ip]=destinations.get(a.destination_ip,0)+1; confidence.append(a.confidence)
    return {"window":window,"alerts":len(rows),"threats_over_time":[{"timestamp":a.timestamp.isoformat(),"count":1,"threat_class":a.threat_class} for a in rows[-300:]],"threat_distribution":by_class,"severity_distribution":by_severity,"confidence_distribution":{"avg":sum(confidence)/len(confidence) if confidence else 0,"high":sum(1 for x in confidence if x>=.9),"medium":sum(1 for x in confidence if .7<=x<.9),"low":sum(1 for x in confidence if x<.7)},"top_destinations":sorted([{"destination":k,"count":v} for k,v in destinations.items()], key=lambda x:-x["count"])[:20]}
