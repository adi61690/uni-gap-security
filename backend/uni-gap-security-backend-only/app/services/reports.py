import csv, json, os
from datetime import datetime, timezone
from pathlib import Path
from openpyxl import Workbook
from sqlalchemy.orm import Session
from sqlalchemy import select
from ..config import get_settings
from ..models import AlertRecord, ReportRecord
settings = get_settings(); Path(settings.report_dir).mkdir(parents=True, exist_ok=True)

def summarize(alerts):
    threat = {}; severity = {}; total_conf = 0.0
    for a in alerts:
        threat[a.threat_class] = threat.get(a.threat_class, 0) + 1
        severity[a.severity] = severity.get(a.severity, 0) + 1
        total_conf += a.confidence
    return {"threat_summary": threat, "severity_summary": severity, "count": len(alerts), "critical": severity.get("Critical", 0), "confidence": total_conf/len(alerts) if alerts else 0}

def generate(db: Session, name: str, export=True):
    alerts = list(db.scalars(select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(5000)))
    summary = summarize(alerts)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.join(settings.report_dir, f"{stamp}_{name.replace(' ', '_')}")
    paths = {}
    payload = {"metadata":{"name":name,"generated_at":datetime.now(timezone.utc).isoformat()}, **summary,
               "evidence":[a.payload.get("evidence", {}) for a in alerts[:100]],
               "alerts":[a.payload for a in alerts]}
    json_path = base + ".json"; csv_path = base + ".csv"; xlsx_path = base + ".xlsx"
    with open(json_path, "w", encoding="utf-8") as f: json.dump(payload, f, indent=2, default=str)
    paths["json"] = json_path
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["timestamp","flow_id","threat_class","subtype","severity","confidence","source_ip","destination_ip","port","protocol"])
        for a in alerts: w.writerow([a.timestamp,a.flow_id,a.threat_class,a.threat_subtype,a.severity,a.confidence,a.source_ip,a.destination_ip,a.destination_port,a.protocol])
    paths["csv"] = csv_path
    wb = Workbook(); ws = wb.active; ws.title = "Summary"
    rows = [("Report", name), ("Generated", payload["metadata"]["generated_at"]), ("Alerts", summary["count"]), ("Critical", summary["critical"]), ("Average confidence", summary["confidence"])]
    for row in rows: ws.append(row)
    ws2 = wb.create_sheet("Alerts"); ws2.append(["timestamp","flow_id","threat_class","subtype","severity","confidence","source_ip","destination_ip","port","protocol"])
    for a in alerts: ws2.append([str(a.timestamp),a.flow_id,a.threat_class,a.threat_subtype,a.severity,a.confidence,a.source_ip,a.destination_ip,a.destination_port,a.protocol])
    wb.save(xlsx_path); paths["xlsx"] = xlsx_path
    rec = ReportRecord(name=name, threat_count=summary["count"], critical_count=summary["critical"], confidence=summary["confidence"], paths=paths)
    db.add(rec); db.commit(); db.refresh(rec)
    return rec, payload
