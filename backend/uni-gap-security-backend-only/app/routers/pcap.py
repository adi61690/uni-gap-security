import asyncio, os
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import PcapJob, User
from ..security import current_user
from ..services.pcap import save_upload
from ..services.audit import record
from ..services.ws import manager
from ..services.ml import predict

router=APIRouter(prefix="/api/v1/pcap", tags=["pcap replay"])

@router.post("/upload")
async def upload(file:UploadFile=File(...), db:Session=Depends(get_db), user:User=Depends(current_user)):
    data=await file.read()
    max_bytes=250*1024*1024
    if len(data)>max_bytes: raise HTTPException(413,"PCAP exceeds configured size limit")
    try: job=save_upload(db,file.filename or "capture.pcap",data)
    except ValueError as e: raise HTTPException(400,str(e))
    record(db,user.display_name,user.role,"PCAP replay uploaded",details={"job_id":job.id,"filename":job.filename})
    return _out(job)

@router.get("")
def list_jobs(db:Session=Depends(get_db), user:User=Depends(current_user)):
    return [_out(x) for x in db.scalars(select(PcapJob).order_by(PcapJob.created_at.desc()).limit(50))]

@router.get("/{job_id}")
def get_job(job_id:int,db:Session=Depends(get_db),user:User=Depends(current_user)):
    job=db.get(PcapJob,job_id)
    if not job: raise HTTPException(404,"PCAP job not found")
    return _out(job)

@router.post("/{job_id}/replay")
async def replay(job_id:int, speed:float=1.0, db:Session=Depends(get_db), user:User=Depends(current_user)):
    job=db.get(PcapJob,job_id)
    if not job: raise HTTPException(404,"PCAP job not found")
    job.status="Replaying"; job.replay_position=0; db.commit()
    record(db,user.display_name,user.role,"PCAP replay started",details={"job_id":job.id,"speed":speed})
    # Safe demo replay: emits observations only; it never transmits packets.
    demo=[{"type":"dns","domain":"x8f92kdl39qmx7z1.com","source_ip":"10.24.3.17","destination_ip":"8.8.8.8","destination_port":53,"protocol":"DNS","dns_query_rate":42.0}, {"type":"encrypted_session","packet_sizes":[120,130,900,850,870,110,105,900,850,870],"timestamps":[0,.5,1,1.5,2,2.5,3,3.5,4,4.5],"source_ip":"10.24.3.17","destination_ip":"172.16.4.8","destination_port":443,"protocol":"TCP","ja3":"ja3_demo","ja4":"ja4_demo","tls_version":"TLS1.3"}]
    for i, event in enumerate(demo,1):
        await asyncio.sleep(max(0.05,0.8/max(speed,0.1)))
        result=predict(event)
        if result.get("is_alert") and result.get("alert"): await manager.broadcast({"type":"replay_alert", **result["alert"]})
        job.replay_position=i/len(demo); db.commit()
    job.status="Completed"; job.replay_position=1; db.commit()
    await manager.broadcast({"type":"pcap_completed","job_id":job.id})
    return _out(job)

@router.post("/{job_id}/reset")
def reset(job_id:int,db:Session=Depends(get_db),user:User=Depends(current_user)):
    job=db.get(PcapJob,job_id)
    if not job: raise HTTPException(404,"PCAP job not found")
    job.status="Ready"; job.replay_position=0; db.commit(); return _out(job)

def _out(job): return {"id":job.id,"filename":job.filename,"size_bytes":job.size_bytes,"packet_count":job.packet_count,"capture_duration":job.capture_duration,"status":job.status,"replay_position":job.replay_position,"created_at":job.created_at.isoformat()}
