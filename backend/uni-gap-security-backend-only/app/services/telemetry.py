import random, asyncio
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..config import get_settings
from ..models import AlertRecord
from .ml import predict
from .ws import manager

settings = get_settings()


def demo_event():
    if random.random() < 0.5:
        domains = ["x8f92kdl39qmx7z1.com", "a9k3m1q7v8z2t4.example.net", "cdn-assets.microsoft.com", "api.github.com"]
        return {"type":"dns", "domain":random.choice(domains), "source_ip":"10.24.3.17", "destination_ip":"8.8.8.8", "destination_port":53, "protocol":"DNS", "dns_record_type":"A", "dns_query_rate":random.uniform(10,80)}
    sizes = [120,130,125,900,850,870,110,105,900,850,870,110]
    ts = [i*0.5 + random.uniform(-0.02,0.02) for i in range(len(sizes))]
    return {"type":"encrypted_session", "packet_sizes":sizes, "timestamps":ts, "ja3":"ja3_demo", "ja4":"ja4_demo", "tls_version":"TLS1.3", "source_ip":"10.24.3.17", "destination_ip":"172.16.4.8", "destination_port":443, "protocol":"TCP"}

async def demo_loop(app):
    while True:
        await asyncio.sleep(settings.demo_stream_interval_seconds)
        if not settings.demo_stream_enabled or not manager.clients: continue
        payload = demo_event()
        try:
            result = predict(payload)
        except Exception:
            continue
        if result.get("is_alert") and result.get("alert"):
            alert = result["alert"]
            await manager.broadcast({"type":"alert", **alert})
            session_factory = app.state.session_factory
            db: Session = session_factory()
            try:
                from datetime import datetime
                data = alert.copy(); data.pop("security_context", None); data["payload"] = alert
                try: dt = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
                except Exception: dt = datetime.now(timezone.utc)
                db.add(AlertRecord(timestamp=dt, flow_id=alert["flow_id"], threat_class=alert["threat_class"], threat_subtype=alert["threat_subtype"], severity=alert["severity"], confidence=alert["confidence"], source_ip=alert["source_ip"], destination_ip=alert["destination_ip"], destination_port=alert["destination_port"], protocol=alert["protocol"], payload=alert))
                db.commit()
            finally: db.close()
