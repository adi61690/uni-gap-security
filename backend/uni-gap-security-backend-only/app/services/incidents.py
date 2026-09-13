from sqlalchemy import select, or_
from sqlalchemy.orm import Session
from ..models import AlertRecord, Incident

def refresh_incident_groups(db: Session):
    alerts = list(db.scalars(select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(500)))
    groups = {}
    for a in alerts:
        key = (a.threat_class, a.destination_ip)
        groups.setdefault(key, []).append(a)
    for (tclass, dest), members in list(groups.items())[:20]:
        key = f"INC-{abs(hash((tclass, dest))) % 9000 + 1000}"
        inc = db.scalar(select(Incident).where(Incident.incident_key == key))
        conf = sum(x.confidence for x in members) / len(members)
        sev = max((x.severity for x in members), key=lambda s: {"Low":1,"Medium":2,"High":3,"Critical":4}.get(s,0))
        if not inc:
            inc = Incident(incident_key=key, title=f"Potential {tclass} Activity", severity=sev, confidence=conf, related_alert_ids=[x.id for x in members])
            db.add(inc)
        else:
            inc.related_alert_ids = [x.id for x in members]; inc.confidence=conf; inc.severity=sev
    db.commit()
    return list(db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(100)))
