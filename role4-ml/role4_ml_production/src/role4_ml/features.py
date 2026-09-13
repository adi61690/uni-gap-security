from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        return ""
    return domain.lower().strip().rstrip(".")


def dns_features(domain: str) -> Dict[str, Any]:
    d = normalize_domain(domain)
    chars = len(d)
    alpha = sum(c.isalpha() for c in d)
    digits = sum(c.isdigit() for c in d)
    specials = chars - alpha - digits
    vowels = sum(c in "aeiou" for c in d if c.isalpha())
    labels = [x for x in d.split(".") if x]
    label_lengths = [len(x) for x in labels]
    qlabel = labels[0] if labels else ""
    ngrams2 = [qlabel[i:i+2] for i in range(max(0, len(qlabel)-1))]
    ngrams3 = [qlabel[i:i+3] for i in range(max(0, len(qlabel)-2))]

    def unique_ratio(xs: Sequence[str]) -> float:
        return len(set(xs)) / len(xs) if xs else 0.0

    def max_freq_ratio(xs: Sequence[str]) -> float:
        if not xs:
            return 0.0
        c = Counter(xs)
        return max(c.values()) / len(xs)

    consonants = sum(c.isalpha() and c not in "aeiou" for c in d)
    numeric_runs = re.findall(r"\d+", d)

    return {
        "dns_length": chars,
        "dns_entropy": shannon_entropy(qlabel),
        "dns_full_entropy": shannon_entropy(d),
        "dns_digit_ratio": digits / chars if chars else 0.0,
        "dns_alpha_ratio": alpha / chars if chars else 0.0,
        "dns_special_ratio": specials / chars if chars else 0.0,
        "dns_label_count": len(labels),
        "dns_max_label_length": max(label_lengths, default=0),
        "dns_avg_label_length": float(np.mean(label_lengths)) if label_lengths else 0.0,
        "dns_consonant_ratio": consonants / alpha if alpha else 0.0,
        "dns_vowel_ratio": vowels / alpha if alpha else 0.0,
        "dns_numeric_runs": len(numeric_runs),
        "dns_hyphen_count": d.count("-"),
        "dns_query_length": len(qlabel),
        "dns_ngram2_unique_ratio": unique_ratio(ngrams2),
        "dns_ngram3_unique_ratio": unique_ratio(ngrams3),
        "dns_ngram2_max_freq": max_freq_ratio(ngrams2),
        "dns_ngram3_max_freq": max_freq_ratio(ngrams3),
        "dns_hex_ratio": sum(c in "0123456789abcdef" for c in qlabel) / len(qlabel) if qlabel else 0.0,
        "dns_base64_like_ratio": sum(c.isalnum() or c in "-_" for c in qlabel) / len(qlabel) if qlabel else 0.0,
    }


def dns_feature_vector(domain: str) -> Dict[str, Any]:
    return dns_features(domain)


def safe_stats(values: Iterable[float]) -> Dict[str, float]:
    arr = np.asarray(list(values), dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "median": 0.0}
    return {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "median": float(np.median(arr)),
    }


def calculate_iat(timestamps: Sequence[float]) -> List[float]:
    if len(timestamps) < 2:
        return []
    ts = np.asarray(timestamps, dtype=float)
    ts = np.sort(ts[np.isfinite(ts)])
    if ts.size < 2:
        return []
    return np.diff(ts).tolist()


def coefficient_of_variation(values: Sequence[float]) -> float:
    stats = safe_stats(values)
    mean = stats["mean"]
    return stats["std"] / mean if mean > 1e-12 else 0.0


def _autocorrelation(x: np.ndarray, lag: int) -> float:
    if x.size <= lag or x.size < 3:
        return 0.0
    a = x[:-lag]
    b = x[lag:]
    a = a - np.mean(a)
    b = b - np.mean(b)
    denom = np.sqrt(np.sum(a * a) * np.sum(b * b))
    return float(np.sum(a * b) / denom) if denom > 1e-12 else 0.0


def periodicity_features(timestamps: Sequence[float]) -> Dict[str, float]:
    iats = np.asarray(calculate_iat(timestamps), dtype=float)
    if iats.size < 3:
        return {"dominant_frequency_hz": 0.0, "fft_magnitude": 0.0, "periodicity_score": 0.0, "autocorrelation_peak": 0.0}
    positive = iats[iats > 0]
    if positive.size < 3:
        return {"dominant_frequency_hz": 0.0, "fft_magnitude": 0.0, "periodicity_score": 0.0, "autocorrelation_peak": 0.0}
    mean_iat = float(np.mean(positive))
    demeaned = positive - np.mean(positive)
    spectrum = np.abs(np.fft.rfft(demeaned))
    freqs = np.fft.rfftfreq(len(demeaned), d=max(mean_iat, 1e-6))
    if spectrum.size > 1:
        idx = int(np.argmax(spectrum[1:]) + 1)
        dom_freq = float(freqs[idx])
        mag = float(spectrum[idx] / max(len(demeaned), 1))
    else:
        dom_freq, mag = 0.0, 0.0
    ac = [_autocorrelation(positive, lag) for lag in range(1, min(8, positive.size - 1) + 1)]
    peak = float(max(ac, default=0.0))
    cv = coefficient_of_variation(positive)
    periodicity = float(np.clip(0.65 * max(peak, 0.0) + 0.35 * (1.0 / (1.0 + cv)), 0.0, 1.0))
    return {
        "dominant_frequency_hz": dom_freq,
        "fft_magnitude": mag,
        "periodicity_score": periodicity,
        "autocorrelation_peak": peak,
    }


def packet_sequence_features(packet_sizes: Sequence[int], timestamps: Sequence[float], ja3: str = "", ja4: str = "", tls_version: str = "", quic: bool = False) -> Dict[str, Any]:
    sizes = np.asarray([abs(float(x)) for x in packet_sizes if x is not None and np.isfinite(x)], dtype=float)
    ts = np.asarray([float(x) for x in timestamps if x is not None and np.isfinite(x)], dtype=float)
    iats = calculate_iat(ts.tolist())
    size_stats = safe_stats(sizes)
    iat_stats = safe_stats(iats)
    p = periodicity_features(ts.tolist())
    signed = np.asarray([float(x) for x in packet_sizes if x is not None and np.isfinite(x)], dtype=float)
    outbound_ratio = float(np.mean(signed > 0)) if signed.size else 0.0
    inbound_ratio = float(np.mean(signed < 0)) if signed.size else 0.0
    size_entropy = shannon_entropy("".join(str(int(min(9999, round(x))))[-2:] for x in sizes)) if sizes.size else 0.0

    return {
        "packet_count": int(sizes.size),
        "packet_size_mean": size_stats["mean"],
        "packet_size_std": size_stats["std"],
        "packet_size_min": size_stats["min"],
        "packet_size_max": size_stats["max"],
        "packet_size_median": size_stats["median"],
        "iat_mean": iat_stats["mean"],
        "iat_std": iat_stats["std"],
        "iat_min": iat_stats["min"],
        "iat_max": iat_stats["max"],
        "iat_median": iat_stats["median"],
        "iat_cv": coefficient_of_variation(iats),
        "outbound_packet_ratio": outbound_ratio,
        "inbound_packet_ratio": inbound_ratio,
        "size_entropy": size_entropy,
        "dominant_frequency_hz": p["dominant_frequency_hz"],
        "fft_magnitude": p["fft_magnitude"],
        "periodicity_score": p["periodicity_score"],
        "autocorrelation_peak": p["autocorrelation_peak"],
        "ja3": ja3 or "UNKNOWN",
        "ja4": ja4 or "UNKNOWN",
        "tls_version": tls_version or "UNKNOWN",
        "quic": bool(quic),
    }


def encrypted_feature_vector(packet_sizes, timestamps, ja3="", ja4="", tls_version="", quic=False) -> Dict[str, Any]:
    return packet_sequence_features(packet_sizes, timestamps, ja3, ja4, tls_version, quic)


def sequence_matrix(packet_sizes: Sequence[float], timestamps: Sequence[float], max_len: int = 64) -> np.ndarray:
    sizes = np.asarray([float(x) for x in packet_sizes if x is not None], dtype=float)
    ts = np.asarray([float(x) for x in timestamps if x is not None], dtype=float)
    if sizes.size == 0:
        return np.zeros((max_len, 2), dtype=np.float32)
    iats = np.asarray(calculate_iat(ts.tolist()), dtype=float)
    if iats.size == 0:
        iats = np.zeros(max(1, sizes.size), dtype=float)
    n = min(max_len, sizes.size)
    size_part = sizes[:n] / max(float(np.percentile(np.abs(sizes), 95)), 1.0)
    iat_n = min(n, iats.size)
    iat_part = iats[:iat_n] / max(float(np.percentile(iats, 95)) if iats.size else 1.0, 1e-3)
    out = np.zeros((max_len, 2), dtype=np.float32)
    out[:n, 0] = np.clip(size_part, -4, 4)
    if iat_n:
        out[:iat_n, 1] = np.clip(iat_part, 0, 4)
    return out
