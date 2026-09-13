from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app

def test_health():
    with TestClient(app) as client:
        r=client.get('/api/v1/health'); assert r.status_code==200; assert r.json()['security']['read_only'] is True

def login(client):
    r=client.post('/api/v1/auth/login',json={'username':'analyst','password':'analyst123'})
    assert r.status_code==200
    return {'Authorization':f"Bearer {r.json()['access_token']}"}

def test_login_and_alerts():
    with TestClient(app) as client:
        h=login(client); r=client.get('/api/v1/alerts/stats',headers=h); assert r.status_code==200

def test_predict():
    from unittest.mock import patch
    fake={
        'is_alert': False,
        'alert': None,
        'model': {'name':'role4','version':'test'},
        'latency_ms': 1
    }
    with TestClient(app) as client:
        h=login(client); payload={'type':'dns','domain':'x8f92kdl39qmx7z1.com','source_ip':'10.24.3.17','destination_ip':'8.8.8.8','destination_port':53,'protocol':'DNS','dns_query_rate':42}
        with patch('app.routers.alerts.predict', return_value=type('R', (), {'model_dump': lambda self: fake, 'is_alert': False, 'alert': None})()):
            r=client.post('/api/v1/alerts/predict',json=payload,headers=h)
        assert r.status_code==200; assert 'is_alert' in r.json()

def test_websocket_contract():
    with TestClient(app) as client:
        with client.websocket_connect('/ws/alerts') as ws:
            msg=ws.receive_json()
            assert msg['type']=='connected'
            ws.send_text('ping')
            assert ws.receive_json()['type']=='pong'


def test_external_ml_health_and_prediction_contract():
    from app.services.ml import health, predict
    with patch("app.services.ml.httpx.Client") as client_cls:
        client = client_cls.return_value.__enter__.return_value
        class Resp:
            def raise_for_status(self): pass
            def json(self): return {"status": "ok"}
        client.get.return_value = Resp()
        assert health()["status"] == "ok"
        client.post.return_value = Resp()
        assert predict({"type": "dns", "domain": "example.com"})["status"] == "ok"
