from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Incident, User
from ..schemas import IncidentUpdate
from ..security import current_user
from ..services.incidents import refresh_incident_groups
from ..services.audit import record

router=APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

@router.get("")
def list_incidents(db: Session=Depends(get_db), user: User=Depends(current_user)):
    return [i.__dict__ | {} for i in refresh_incident_groups(db)]

@router.patch("/{incident_id}")
def update_incident(incident_id:int, req:IncidentUpdate, db:Session=Depends(get_db), user:User=Depends(current_user)):
    inc=db.get(Incident,incident_id)
    if not inc: raise HTTPException(404,"Incident not found")
    if req.status: inc.status=req.status
    if req.note is not None: inc.note=req.note
    db.commit(); record(db,user.display_name,user.role,"Incident updated",details={"incident_id":incident_id,"status":inc.status})
    return {"id":inc.id,"incident_key":inc.incident_key,"title":inc.title,"severity":inc.severity,"confidence":inc.confidence,"status":inc.status,"note":inc.note,"related_alert_ids":inc.related_alert_ids}
