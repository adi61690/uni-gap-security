from __future__ import annotations
import hashlib, math, ipaddress
from collections import Counter
from typing import Iterable

def entropy(values: Iterable[str]) -> float:
    vals=[str(v) for v in values if v is not None]
    if not vals: return 0.0
    counts=Counter(vals); n=len(vals)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

def safe_rate(value: float, duration: float) -> float:
    return float(value / duration) if duration > 0 else 0.0

def stable_flow_id(src_ip, src_port, dst_ip, dst_port, protocol):
    key=f'{src_ip}:{src_port}>{dst_ip}:{dst_port}/{protocol}'.encode()
    return 'F-'+hashlib.sha256(key).hexdigest()[:12].upper()

def symmetry(forward_bytes: int, reverse_bytes: int) -> float:
    total=forward_bytes+reverse_bytes
    if total==0: return 0.0
    return 1.0 - abs(forward_bytes-reverse_bytes)/total

def coefficient_of_variation(values: list[float]) -> float:
    if len(values)<2: return 0.0
    mean=sum(values)/len(values)
    if mean<=0: return 0.0
    var=sum((x-mean)**2 for x in values)/len(values)
    return math.sqrt(var)/mean

def burstiness(values: list[float]) -> float:
    # normalized burstiness in [-1,1] for inter-arrival samples.
    if len(values)<2: return 0.0
    mean=sum(values)/len(values)
    if mean<=0: return 0.0
    sd=math.sqrt(sum((x-mean)**2 for x in values)/len(values))
    return float((sd-mean)/(sd+mean)) if (sd+mean)>0 else 0.0

def normalize_protocol(proto: str, src_port=None, dst_port=None) -> str:
    p=(proto or 'OTHER').upper()
    if p in {'TCP','UDP','ICMP','QUIC'}: return p
    if p in {'6','17','1'}: return {'6':'TCP','17':'UDP','1':'ICMP'}[p]
    if src_port in {53} or dst_port in {53}: return 'DNS'
    if src_port in {443,8443} or dst_port in {443,8443}: return 'TLS' if p=='TCP' else 'QUIC' if p=='UDP' else p
    return p

def ip_family(ip: str) -> int:
    try: return ipaddress.ip_address(ip).version
    except ValueError: return 0
