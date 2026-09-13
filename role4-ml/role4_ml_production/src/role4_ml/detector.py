from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import numpy as np
from catboost import CatBoostClassifier

from .constants import MODEL_VERSION, ThreatClass
from .evidence import dns_evidence, encrypted_evidence, severity_for
from .features import dns_feature_vector, encrypted_feature_vector, sequence_matrix
from .heuristics import dns_heuristic_label, encrypted_heuristic_label
from .schemas import Alert, Evidence, ModelInfo, PredictRequest, PredictResponse
from .sequence_model import load_sequence_model, predict_sequence

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR = os.path.join(BASE_DIR, "models")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Role4Detector:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.dns_model = None
        self.encrypted_model = None
        self.dns_metadata: Dict[str, Any] = {}
        self.encrypted_metadata: Dict[str, Any] = {}
        self.baseline: Dict[str, Any] = {}
        self.sequence = None
        dns_cbm = os.path.join(model_dir, "dns_catboost.cbm")
        enc_cbm = os.path.join(model_dir, "encrypted_catboost.cbm")
        dns_meta = os.path.join(model_dir, "dns_catboost_metadata.json")
        enc_meta = os.path.join(model_dir, "encrypted_catboost_metadata.json")
        seq = os.path.join(model_dir, "role4_sequence_lstm.pt")
        baseline_file = os.path.join(model_dir, "baseline_profile.json")
        if os.path.exists(dns_cbm):
            self.dns_model = CatBoostClassifier()
            self.dns_model.load_model(dns_cbm)
        if os.path.exists(enc_cbm):
            self.encrypted_model = CatBoostClassifier()
            self.encrypted_model.load_model(enc_cbm)
        if os.path.exists(dns_meta):
            with open(dns_meta, "r", encoding="utf-8") as f:
                self.dns_metadata = json.load(f)
        if os.path.exists(enc_meta):
            with open(enc_meta, "r", encoding="utf-8") as f:
                self.encrypted_metadata = json.load(f)
        if os.path.exists(seq):
            self.sequence = load_sequence_model(seq, classes=3)
        if os.path.exists(baseline_file):
            with open(baseline_file, "r", encoding="utf-8") as f:
                self.baseline = json.load(f)

    def _cat_predict(self, features: Dict[str, Any], kind: str) -> Tuple[str, float, Dict[str, float]]:
        model = self.dns_model if kind == "dns" else self.encrypted_model
        metadata = self.dns_metadata if kind == "dns" else self.encrypted_metadata
        if model is None:
            raise RuntimeError("Required CatBoost model not found. Run: python scripts/train_all.py")
        columns = metadata.get("features", list(features.keys()))
        row = {c: features.get(c, "UNKNOWN" if c in metadata.get("categorical_features", []) else 0.0) for c in columns}
        for c in metadata.get("categorical_features", []):
            row[c] = str(row.get(c, "UNKNOWN"))
        import pandas as pd
        frame = pd.DataFrame([row], columns=columns)
        probs = model.predict_proba(frame)[0]
        classes = [str(c) for c in model.classes_]
        idx = int(np.argmax(probs))
        return classes[idx], float(probs[idx]), {classes[i]: float(probs[i]) for i in range(len(classes))}

    def predict_dns(self, req: PredictRequest) -> PredictResponse:
        start = time.perf_counter()
        features = dns_feature_vector(req.domain or "")
        evidence = dns_evidence(features, req.dns_query_rate, req.dns_record_type, self.baseline.get("dns", {}))
        heuristic = dns_heuristic_label(features)
        try:
            label, conf, scores = self._cat_predict({**features, "dns_record_type": req.dns_record_type}, "dns")
        except Exception:
            label, conf, scores = heuristic, float(evidence["anomaly_score"]), {}
        if label == "DGA":
            threat_class, subtype = ThreatClass.DGA_DNS.value, "DGA"
        elif label == "DNS_TUNNELING":
            threat_class, subtype = ThreatClass.DGA_DNS.value, "DNS Tunneling"
        elif label == "BENIGN_DNS":
            threat_class, subtype = ThreatClass.DGA_DNS.value, "Benign DNS"
        else:
            threat_class, subtype = ThreatClass.DGA_DNS.value, str(label)
        if label == "BENIGN_DNS" and conf < 0.80:
            return PredictResponse(is_alert=False, observation={"features": features, "evidence": evidence, "model": "role4_dns"})
        severity = severity_for(conf, evidence["anomaly_score"])
        latency = (time.perf_counter() - start) * 1000
        alert = self._make_alert(req, threat_class, subtype, conf, severity, evidence, scores, latency, "role4_dns")
        return PredictResponse(is_alert=True, alert=alert, observation={"features": features, "evidence": evidence})

    def predict_encrypted(self, req: PredictRequest) -> PredictResponse:
        start = time.perf_counter()
        features = encrypted_feature_vector(req.packet_sizes, req.timestamps, req.ja3, req.ja4, req.tls_version, req.quic)
        evidence = encrypted_evidence(features, self.baseline.get("encrypted", {}))
        heuristic = encrypted_heuristic_label(features)
        try:
            label, conf, scores = self._cat_predict(features, "encrypted")
        except Exception:
            label, conf, scores = heuristic, float(evidence["anomaly_score"]), {}
        sequence_used = False
        if self.sequence is not None and len(req.packet_sizes) >= 4:
            idx, probs = predict_sequence(self.sequence, sequence_matrix(req.packet_sizes, req.timestamps))
            seq_classes = ["BENIGN_ENCRYPTED", "ENCRYPTED_MALWARE", "BOTNET_C2"]
            seq_label = seq_classes[idx]
            seq_conf = float(probs[idx])
            sequence_used = True
            if seq_conf > conf:
                label, conf = seq_label, seq_conf
            scores = {**scores, **{f"sequence::{seq_classes[i]}": float(probs[i]) for i in range(len(probs))}}
        if label == "BENIGN_ENCRYPTED" and conf < 0.80:
            return PredictResponse(is_alert=False, observation={"features": features, "evidence": evidence, "model": "role4_encrypted", "sequence_model_used": sequence_used})
        if label == "BOTNET_C2":
            threat_class, subtype = ThreatClass.BOTNET_C2.value, "Encrypted Beaconing"
        else:
            threat_class, subtype = ThreatClass.ENCRYPTED_MALWARE.value, "Encrypted Session Anomaly"
        severity = severity_for(conf, evidence["anomaly_score"])
        latency = (time.perf_counter() - start) * 1000
        alert = self._make_alert(req, threat_class, subtype, conf, severity, evidence, scores, latency, "role4_encrypted", sequence_used)
        return PredictResponse(is_alert=True, alert=alert, observation={"features": features, "evidence": evidence})

    def predict(self, req: PredictRequest) -> PredictResponse:
        if req.type == "dns":
            return self.predict_dns(req)
        return self.predict_encrypted(req)

    def _make_alert(self, req, threat_class, subtype, confidence, severity, evidence, scores, latency, model_name, sequence_used=False) -> Alert:
        evidence_model = Evidence(**{k: v for k, v in evidence.items() if k in Evidence.model_fields})
        evidence_model.feature_values = evidence_model.feature_values or {}
        evidence_model.feature_values.update(evidence)
        return Alert(
            timestamp=req.timestamp or now_iso(),
            flow_id=req.flow_id or f"FLOW-{uuid.uuid4().hex[:6].upper()}",
            threat_class=threat_class,
            threat_subtype=subtype,
            severity=severity,
            confidence=float(np.clip(confidence, 0, 1)),
            source_ip=req.source_ip,
            destination_ip=req.destination_ip,
            destination_port=req.destination_port,
            protocol=req.protocol,
            evidence=evidence_model,
            model=ModelInfo(name=model_name, version=MODEL_VERSION, latency_ms=round(latency, 2), class_scores=scores, sequence_model_used=sequence_used, model_type="CatBoost + LSTM" if sequence_used else "CatBoost"),
            evidence_summary=evidence.get("explanation", "Observed metadata differs from the learned baseline."),
        )
