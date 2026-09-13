import asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from .config import get_settings
from .db import Base, engine, SessionLocal
from .models import User
from .security import hash_password
from .routers import auth, alerts, analytics, incidents, hunt, pcap, reports, audit, settings as settings_router, system, ingest
from .routers.alerts import websocket_handler
from .services.telemetry import demo_loop

settings=get_settings()

def init_db():
    os.makedirs("data",exist_ok=True); os.makedirs(settings.upload_dir,exist_ok=True); os.makedirs(settings.report_dir,exist_ok=True)
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        user=db.scalar(select(User).where(User.username=="analyst"))
        if not user:
            db.add(User(username="analyst",password_hash=hash_password("analyst123"),role="Analyst",display_name="Analyst")); db.commit()
    finally: db.close()

@asynccontextmanager
async def lifespan(app:FastAPI):
    init_db(); app.state.session_factory=SessionLocal
    task = asyncio.create_task(demo_loop(app)) if settings.demo_stream_enabled else None
    try: yield
    finally:
        if task:
            task.cancel()

app=FastAPI(title=settings.app_name,version="1.0.0",description="Passive one-way security monitoring backend integrating Uni-Gap frontend with the external Role 4 ML service.",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_list,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.include_router(auth.router); app.include_router(alerts.router); app.include_router(ingest.router); app.include_router(analytics.router); app.include_router(incidents.router); app.include_router(hunt.router); app.include_router(pcap.router); app.include_router(reports.router); app.include_router(audit.router); app.include_router(settings_router.router); app.include_router(system.router)

@app.websocket("/ws/alerts")
async def ws_alerts(ws:WebSocket): await websocket_handler(ws)

@app.get("/")
def root(): return {"service":settings.app_name,"docs":"/docs","websocket":"/ws/alerts","security":"read-only one-way metadata analysis"}
