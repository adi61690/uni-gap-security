from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User
from ..security import current_user
from ..services.ml import predict
from ..routers.alerts import _save_alert
from ..services.ws import manager

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])

@router.post("/flow")
async def ingest_flow(payload: dict, db: Session = Depends(get_db), user: User = Depends(current_user)):
    result = predict(payload)
    if result.get("is_alert") and result.get("alert"):
        _save_alert(db, result["alert"])
        await manager.broadcast({"type": "alert", **result["alert"]})
    return result
