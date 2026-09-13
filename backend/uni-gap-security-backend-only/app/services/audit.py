from sqlalchemy.orm import Session
from ..models import AuditEvent

def record(db: Session, analyst: str, role: str, event: str, session_id: str | None = None, status: str = "SUCCESS", details: dict | None = None):
    item = AuditEvent(analyst=analyst, role=role, event=event, status=status, session_id=session_id, details=details or {})
    db.add(item); db.commit(); db.refresh(item); return item
