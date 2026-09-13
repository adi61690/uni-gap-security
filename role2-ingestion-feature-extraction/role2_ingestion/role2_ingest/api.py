from __future__ import annotations
import os, tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from .ingest import IngestionEngine
from .models import FlowFeatures
from .handoff import Role4Client

app=FastAPI(title='Uni-Gap Role 2 — Passive Ingestion & Feature Extraction',version='2.0.0')
_engine=IngestionEngine(timeout=int(os.getenv('ROLE2_FLOW_TIMEOUT_SECONDS','60')),export_path=os.getenv('ROLE2_EXPORT_JSONL','./data/role2_features.jsonl'))

class PCAPRequest(BaseModel): path:str; max_packets:int|None=None
class FlowRecordRequest(BaseModel): source:str='netflow'; record:dict

@app.get('/health')
def health():
    return {'status':'ok','role':'role2_ingestion','schema_version':'role2.v2','read_only':True,'active_probing':False,'return_path':False,'payload_decryption':False,'payload_persistence':False,'role4_service':os.getenv('ROLE4_SERVICE_URL','http://localhost:8001')}

@app.post('/ingest/pcap')
def ingest_pcap(req:PCAPRequest):
    if not os.path.exists(req.path): raise HTTPException(404,'PCAP/PCAPNG path not found')
    flows=_engine.ingest_pcap(req.path,max_packets=req.max_packets)
    return {'source':'pcap','flows':len(flows),'features':[f.model_dump() for f in flows]}

@app.post('/ingest/upload')
async def ingest_upload(file:UploadFile=File(...)):
    name=(file.filename or 'capture.pcap').lower()
    if not name.endswith(('.pcap','.pcapng','.cap')): raise HTTPException(400,'Expected a PCAP/PCAPNG capture')
    suffix=os.path.splitext(name)[1] or '.pcap'
    with tempfile.NamedTemporaryFile(delete=False,suffix=suffix) as tmp:
        tmp.write(await file.read()); path=tmp.name
    try:
        flows=_engine.ingest_pcap(path)
        return {'filename':file.filename,'flows':len(flows),'features':[f.model_dump() for f in flows]}
    finally:
        try: os.unlink(path)
        except OSError: pass

@app.post('/ingest/zeek')
def ingest_zeek(req:PCAPRequest):
    if not os.path.exists(req.path): raise HTTPException(404,'Zeek JSON file not found')
    flows=_engine.ingest_zeek_json(req.path)
    return {'source':'zeek','flows':len(flows),'features':[f.model_dump() for f in flows]}

@app.post('/ingest/flow-record')
def ingest_flow_record(req:FlowRecordRequest):
    flows=_engine.ingest_flow_record(req.record,req.source)
    return {'source':req.source,'flows':len(flows),'features':[f.model_dump() for f in flows]}

@app.post('/role4/predict')
def role4_predict(feature: dict):
    try:
        result=Role4Client().predict(feature); return result
    except Exception as exc:
        raise HTTPException(503,f'Role 4 ML service unavailable: {exc}') from exc
