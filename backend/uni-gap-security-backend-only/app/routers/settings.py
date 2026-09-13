from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import AppSetting, User
from ..schemas import SettingUpdate, ConnectionTestRequest
from ..security import current_user
from ..services.audit import record

router=APIRouter(prefix="/api/v1/settings",tags=["settings"])
DEFAULT={"theme":"system","density":"comfortable","animations":True,"reducedMotion":False,"confidenceThreshold":70,"liveNotifications":True,"sound":False,"websocketEndpoint":"ws://localhost:8000/ws/alerts","database":{"type":"PostgreSQL","host":"","port":5432,"database":"","username":"","password":""}}

@router.get("")
def get_settings(db:Session=Depends(get_db),user:User=Depends(current_user)):
    item=db.scalar(select(AppSetting).where(AppSetting.user_id==user.id)); return {"values":item.values if item else DEFAULT}

@router.put("")
def update_settings(req:SettingUpdate,db:Session=Depends(get_db),user:User=Depends(current_user)):
    item=db.scalar(select(AppSetting).where(AppSetting.user_id==user.id))
    if not item: item=AppSetting(user_id=user.id,values=req.values); db.add(item)
    else: item.values=req.values
    db.commit(); record(db,user.display_name,user.role,"Settings changed",details=req.values); return {"values":item.values}

@router.post("/test-connection")
def test_connection(req:ConnectionTestRequest,user:User=Depends(current_user)):
    # Prototype-safe: this endpoint never opens a network or DB connection from the browser.
    if req.kind not in {"websocket","database"}: return {"status":"error","message":"Unsupported connection type"}
    return {"status":"connected","simulated":True,"kind":req.kind,"endpoint":req.endpoint}
