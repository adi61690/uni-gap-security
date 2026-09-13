import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import ReportRecord, User
from ..schemas import ReportRequest
from ..security import current_user
from ..services.reports import generate
from ..services.audit import record

router=APIRouter(prefix="/api/v1/reports",tags=["reports"])

@router.get("")
def list_reports(db:Session=Depends(get_db),user:User=Depends(current_user)):
    return [{"id":r.id,"name":r.name,"generated_at":r.generated_at.isoformat(),"threat_count":r.threat_count,"critical_count":r.critical_count,"confidence":r.confidence,"status":r.status} for r in db.scalars(select(ReportRecord).order_by(ReportRecord.generated_at.desc()).limit(50))]

@router.post("")
def create_report(req:ReportRequest,db:Session=Depends(get_db),user:User=Depends(current_user)):
    rec,payload=generate(db,req.name,req.export); record(db,user.display_name,user.role,"Report generated",details={"report_id":rec.id})
    return {"id":rec.id,"name":rec.name,"generated_at":rec.generated_at.isoformat(),"summary":{k:payload[k] for k in ["threat_summary","severity_summary","count","critical","confidence"]},"files":rec.paths}

@router.get("/{report_id}/download/{kind}")
def download(report_id:int,kind:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    rec=db.get(ReportRecord,report_id)
    if not rec: raise HTTPException(404,"Report not found")
    path=rec.paths.get(kind)
    if not path or not os.path.exists(path): raise HTTPException(404,"Export not found")
    return FileResponse(path,filename=os.path.basename(path))
