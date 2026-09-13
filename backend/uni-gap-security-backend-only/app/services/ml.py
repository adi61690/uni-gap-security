from __future__ import annotations

from typing import Any
import httpx
from fastapi import HTTPException
from ..config import get_settings

settings = get_settings()

def _post(base_url: str, path: str, payload: dict) -> dict:
    try:
        with httpx.Client(timeout=settings.ml_service_timeout_seconds) as client:
            response = client.post(base_url.rstrip("/") + path, json=payload)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"ML service returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="ML service unavailable") from exc

def _get(base_url: str, path: str) -> dict:
    try:
        with httpx.Client(timeout=min(settings.ml_service_timeout_seconds, 5.0)) as client:
            response = client.get(base_url.rstrip("/") + path)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError:
        return {"status": "unavailable"}

def _looks_like_role2_flow(payload: dict) -> bool:
    return payload.get("schema_version", "").startswith("role2.") and "flow_id" in payload

def _role4_event_from_flow(payload: dict) -> dict | None:
    protocol = str(payload.get("protocol", "")).upper()
    tls = payload.get("tls_metadata") or {}
    quic = payload.get("quic_metadata") or {}
    if not (protocol in {"DNS", "TLS", "QUIC"} or tls or quic or payload.get("packet_sizes")):
        return None
    if protocol == "DNS":
        return {
            "type": "dns",
            "timestamp": payload.get("timestamp_end"),
            "flow_id": payload.get("flow_id"),
            "source_ip": payload.get("src_ip", "0.0.0.0"),
            "destination_ip": payload.get("dst_ip", "0.0.0.0"),
            "destination_port": payload.get("dst_port") or 53,
            "protocol": "DNS",
            "domain": tls.get("domain") or payload.get("domain"),
            "dns_record_type": tls.get("dns_record_type", "A"),
            "dns_query_rate": payload.get("packet_rate", 0.0),
        }
    return {
        "type": "encrypted_session",
        "timestamp": payload.get("timestamp_end"),
        "flow_id": payload.get("flow_id"),
        "source_ip": payload.get("src_ip", "0.0.0.0"),
        "destination_ip": payload.get("dst_ip", "0.0.0.0"),
        "destination_port": payload.get("dst_port") or 443,
        "protocol": protocol or "TCP",
        "ja3": tls.get("ja3", ""),
        "ja4": tls.get("ja4", ""),
        "tls_version": tls.get("version", tls.get("tls_version", "")),
        "quic": protocol == "QUIC" or bool(quic),
        "packet_sizes": payload.get("packet_sizes", []),
        "timestamps": payload.get("inter_arrival_times", []),
    }

def predict_role3(payload: dict) -> dict:
    if not settings.role3_service_enabled:
        return {"is_alert": False, "service": "role3", "disabled": True}
    return _post(settings.role3_service_url, "/predict", payload)

def predict_role4(payload: dict) -> dict:
    if not settings.ml_service_enabled:
        return {"is_alert": False, "service": "role4", "disabled": True}
    return _post(settings.ml_service_url, "/predict", payload)

def predict(payload: dict):
    """Route a direct Role 4 event or a Role 2 flow to the correct ML service(s)."""
    if _looks_like_role2_flow(payload):
        results: list[dict] = []
        try:
            results.append(predict_role3(payload))
        except HTTPException:
            results.append({"is_alert": False, "service": "role3", "error": "unavailable"})
        r4 = _role4_event_from_flow(payload)
        if r4:
            try:
                results.append(predict_role4(r4))
            except HTTPException:
                results.append({"is_alert": False, "service": "role4", "error": "unavailable"})
        alerts = [r.get("alert") for r in results if r.get("is_alert") and r.get("alert")]
        if alerts:
            alerts.sort(key=lambda a: float(a.get("confidence", 0)), reverse=True)
            return {"is_alert": True, "alert": alerts[0], "sources": results, "observation": {"source": "role2"}}
        return {"is_alert": False, "alert": None, "sources": results, "observation": {"source": "role2"}}
    if payload.get("type") in {"dns", "encrypted_session"}:
        return predict_role4(payload)
    return predict_role3(payload)

def health() -> dict:
    role3 = _get(settings.role3_service_url, "/health") if settings.role3_service_enabled else {"status": "disabled"}
    role4 = _get(settings.ml_service_url, "/health") if settings.ml_service_enabled else {"status": "disabled"}
    overall = "ok" if (role3.get("status") == "ok" or role4.get("status") == "ok") else "unavailable"
    return {"status": overall, "role3": role3, "role4": role4}
