from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
try:
    from scapy.all import wrpcap
except Exception:
    wrpcap = None

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def write_pcap(packets, path: str) -> None:
    if wrpcap is None:
        raise RuntimeError("Scapy is required to write PCAP files. Run: pip install -r requirements.txt")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(path, packets)

def write_jsonl(records: Iterable[dict], path: str) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            if is_dataclass(record):
                record = asdict(record)
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
            count += 1
    return count

def write_manifest(path: str, manifest: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
