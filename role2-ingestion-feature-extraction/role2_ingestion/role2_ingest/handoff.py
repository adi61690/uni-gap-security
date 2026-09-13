from __future__ import annotations
import os
import httpx
from .models import FlowFeatures

class Role4Client:
    def __init__(self, base_url: str|None=None, timeout: float=5.0):
        self.base_url=(base_url or os.getenv('ROLE4_SERVICE_URL','http://localhost:8001')).rstrip('/')
        self.timeout=timeout
    def health(self):
        with httpx.Client(timeout=self.timeout) as c:
            r=c.get(self.base_url+'/health'); r.raise_for_status(); return r.json()
    def predict(self, feature: FlowFeatures|dict):
        payload=feature.model_dump() if isinstance(feature,FlowFeatures) else feature
        # Explicitly remove any accidental payload-like keys.
        payload.pop('payload',None); payload.pop('raw',None); payload.pop('payload_bytes',None)
        with httpx.Client(timeout=self.timeout) as c:
            r=c.post(self.base_url+'/predict',json=payload); r.raise_for_status(); return r.json()

class BackendPublisher:
    """Optional publisher for a backend ingestion endpoint when deployed.
    The default backend package can consume predictions; this publisher is disabled by default.
    """
    def __init__(self, base_url: str|None=None, enabled: bool=False, timeout: float=5.0):
        self.base_url=(base_url or os.getenv('BACKEND_INGEST_URL','')).rstrip('/')
        self.enabled=enabled and bool(self.base_url); self.timeout=timeout
    def publish(self, feature: FlowFeatures|dict):
        if not self.enabled: return {'enabled':False}
        payload=feature.model_dump() if isinstance(feature,FlowFeatures) else feature
        with httpx.Client(timeout=self.timeout) as c:
            r=c.post(self.base_url,json=payload); r.raise_for_status(); return r.json() if r.content else {'ok':True}
