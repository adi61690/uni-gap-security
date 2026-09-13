import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User, SessionRecord
from ..schemas import LoginRequest, LoginResponse
from ..security import verify_password, create_token, current_user
from ..services.audit import record

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == req.username))
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    session_id = uuid.uuid4().hex
    session = SessionRecord(session_id=session_id, user_id=user.id)
    db.add(session); db.commit()
    record(db, user.display_name, user.role, "Login", session_id)
    token = create_token(user, session_id)
    return {"access_token":token,"token_type":"bearer","session_id":session_id,"user":{"id":user.id,"username":user.username,"display_name":user.display_name,"role":user.role}}

@router.post("/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    # The client token is stateless; close all active sessions for this user.
    sessions = list(db.scalars(select(SessionRecord).where(SessionRecord.user_id==user.id, SessionRecord.active==True)))
    from datetime import datetime, timezone
    for s in sessions: s.active=False; s.ended_at=datetime.now(timezone.utc)
    db.commit(); record(db, user.display_name, user.role, "Logout", None)
    return {"status":"ok"}

@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"id":user.id,"username":user.username,"display_name":user.display_name,"role":user.role}
