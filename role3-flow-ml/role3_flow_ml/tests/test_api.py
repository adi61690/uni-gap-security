import sys
sys.path.insert(0,'src')
from fastapi.testclient import TestClient
from role3_ml.api import app

def test_health():
    c=TestClient(app); r=c.get('/health'); assert r.status_code==200; assert r.json()['service']=='role3_ml'
