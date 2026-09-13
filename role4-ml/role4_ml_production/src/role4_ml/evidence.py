from __future__ import annotations

from typing import Any, Dict
import numpy as np


def severity_for(confidence: float, anomaly_score: float = 0.0) -> str:
    score = max(confidence, anomaly_score)
    if score >= 0.97:
        return "Critical"
    if score >= 0.90:
        return "High"
    if score >= 0.78:
        return "Medium"
    return "Low"


def _range_lookup(baseline, key, default_low=0.0, default_high=0.0):
    item = (baseline or {}).get(key, {})
    return float(item.get("p05", default_low)), float(item.get("p95", default_high))

def dns_evidence(features: Dict[str, Any], query_rate: float = 0.0, record_type: str = "A", baseline: Dict[str, Any] | None = None) -> Dict[str, Any]:
    baseline = baseline or {}
    entropy_low, entropy_high = _range_lookup(baseline, "dns_entropy", 2.0, 4.0)
    length_low, length_high = _range_lookup(baseline, "dns_query_length", 3.0, 24.0)
    anomaly = 0.0
    entropy_scale = max(entropy_high - entropy_low, 0.5)
    length_scale = max(length_high - length_low, 1.0)
    anomaly += min(1.0, max(0.0, (features.get("dns_entropy", 0.0) - entropy_high) / entropy_scale)) * 0.35
    anomaly += min(1.0, max(0.0, (features.get("dns_query_length", 0.0) - length_high) / length_scale)) * 0.25
    anomaly += min(1.0, max(0.0, features.get("dns_ngram3_unique_ratio", 0.0))) * 0.20
    anomaly += min(1.0, max(0.0, query_rate / 60.0)) * 0.20
    anomaly = float(np.clip(anomaly, 0.0, 1.0))
    ngram_score = float(np.clip((features.get("dns_ngram3_unique_ratio", 0.0) + features.get("dns_hex_ratio", 0.0)) / 2.0, 0.0, 1.0))
    explanation = "Lexical behavior is anomalous relative to the learned baseline." if anomaly >= 0.55 else "Observed DNS lexical behavior is within the learned baseline range."
    return {"dns_entropy": float(features.get("dns_entropy", 0.0)), "dns_query_length": int(features.get("dns_query_length", 0)), "dns_ngram_score": ngram_score, "dns_query_rate": query_rate, "dns_record_type": record_type, "normal_range": {"dns_entropy": [entropy_low, entropy_high], "dns_query_length": [length_low, length_high]}, "anomaly_score": anomaly, "explanation": explanation}


def encrypted_evidence(features: Dict[str, Any], baseline: Dict[str, Any] | None = None) -> Dict[str, Any]:
    baseline = baseline or {}
    periodicity = float(features.get("periodicity_score", 0.0))
    p_low, p_high = _range_lookup(baseline, "periodicity_score", 0.0, 0.35)
    iat_cv = float(features.get("iat_cv", 0.0))
    anomaly = float(np.clip(0.55 * periodicity + 0.25 * (1.0 - min(iat_cv, 1.0)) + 0.20 * min(features.get("packet_count", 0) / 64.0, 1.0), 0.0, 1.0))
    return {
        "iat_cv": iat_cv,
        "periodicity_score": periodicity,
        "dominant_frequency_hz": float(features.get("dominant_frequency_hz", 0.0)),
        "fft_magnitude": float(features.get("fft_magnitude", 0.0)),
        "autocorrelation_peak": float(features.get("autocorrelation_peak", 0.0)),
        "ja3": features.get("ja3"),
        "ja4": features.get("ja4"),
        "packet_size_statistics": {
            "mean": float(features.get("packet_size_mean", 0.0)),
            "std": float(features.get("packet_size_std", 0.0)),
            "min": float(features.get("packet_size_min", 0.0)),
            "max": float(features.get("packet_size_max", 0.0)),
            "median": float(features.get("packet_size_median", 0.0)),
        },
        "timing_statistics": {
            "mean": float(features.get("iat_mean", 0.0)),
            "std": float(features.get("iat_std", 0.0)),
            "min": float(features.get("iat_min", 0.0)),
            "max": float(features.get("iat_max", 0.0)),
            "median": float(features.get("iat_median", 0.0)),
        },
        "normal_range": {"periodicity_score": [p_low, p_high]},
        "anomaly_score": anomaly,
        "explanation": "Encrypted session metadata is anomalous; payload content was not decrypted." if anomaly >= 0.55 else "Encrypted session metadata is within the learned baseline range; payload content was not decrypted.",
    }
