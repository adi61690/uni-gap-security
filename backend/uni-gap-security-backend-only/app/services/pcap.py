import os, uuid
from pathlib import Path
from sqlalchemy.orm import Session
from ..config import get_settings
from ..models import PcapJob
settings = get_settings()
Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

def inspect_pcap(path: str):
    try:
        from scapy.utils import RawPcapReader
        count = 0; first = last = None
        for pkt_data, meta in RawPcapReader(path):
            count += 1
            sec = getattr(meta, "sec", None); usec = getattr(meta, "usec", 0)
            if sec is not None:
                t = sec + usec / 1_000_000
                first = t if first is None else first
                last = t
            if count >= 1000000: break
        duration = max(0.0, (last - first)) if first is not None and last is not None else 0.0
        return count, duration
    except Exception:
        return 0, 0.0

def save_upload(db: Session, filename: str, contents: bytes):
    ext = Path(filename).suffix.lower()
    if ext not in {".pcap", ".pcapng"}: raise ValueError("Only PCAP and PCAPNG are supported")
    safe = f"{uuid.uuid4().hex}_{Path(filename).name}"
    path = os.path.join(settings.upload_dir, safe)
    with open(path, "wb") as f: f.write(contents)
    count, duration = inspect_pcap(path)
    job = PcapJob(filename=filename, path=path, size_bytes=len(contents), packet_count=count, capture_duration=duration, status="Ready")
    db.add(job); db.commit(); db.refresh(job); return job
