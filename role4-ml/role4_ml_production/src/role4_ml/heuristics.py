from __future__ import annotations

from typing import Dict, Any


def dns_heuristic_label(features: Dict[str, Any]) -> str:
    entropy = features.get("dns_entropy", 0.0)
    length = features.get("dns_query_length", 0)
    digit_ratio = features.get("dns_digit_ratio", 0.0)
    if length >= 35 and entropy >= 3.8 and digit_ratio >= 0.15:
        return "DNS_TUNNELING"
    if length >= 16 and entropy >= 3.3:
        return "DGA"
    return "BENIGN_DNS"


def encrypted_heuristic_label(features: Dict[str, Any]) -> str:
    p = features.get("periodicity_score", 0.0)
    cv = features.get("iat_cv", 0.0)
    count = features.get("packet_count", 0)
    if p >= 0.72 and cv <= 0.35 and count >= 8:
        return "BOTNET_C2"
    if p >= 0.52 or features.get("ja3", "UNKNOWN") != "UNKNOWN" or features.get("ja4", "UNKNOWN") != "UNKNOWN":
        return "ENCRYPTED_MALWARE"
    return "BENIGN_ENCRYPTED"
