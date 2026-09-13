from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import base64, random, string
from typing import Any

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
except Exception:
    Ether = IP = TCP = UDP = Raw = DNS = DNSQR = DNSRR = None

@dataclass
class Label:
    timestamp: str
    scenario: str
    label: str
    flow_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_index: int
    features_hint: dict[str, Any]

    def to_dict(self):
        return asdict(self)

def _ts(base, offset):
    return (base + timedelta(seconds=offset)).isoformat()

def _require_scapy():
    if IP is None:
        raise RuntimeError("Scapy is required for PCAP generation. Run: pip install -r requirements.txt")

def benign(count: int, seed: int, src="10.10.1.10", dst="10.10.2.20"):
    _require_scapy(); rng = random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]
    for i in range(count):
        sport=30000+(i%20000); dport=rng.choice([80,443,53,123,22,8080]); proto=UDP if dport in [53,123] else TCP
        payload=b"U"*rng.randint(64,512)
        if proto is TCP:
            p=Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="A")/Raw(load=payload)
            protocol="TCP"
        else:
            p=Ether()/IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/Raw(load=payload)
            protocol="UDP"
        p.time=(base+timedelta(seconds=i*0.01)).timestamp(); packets.append(p)
        labels.append(Label(_ts(base,i*0.01),"benign","benign",f"BEN-{i:06d}",src,dst,protocol,sport,dport,i,{"pattern":"baseline"}).to_dict())
    return packets, labels

def syn_flood(count:int, seed:int, src_base="10.20.0.10", dst="10.20.1.20"):
    _require_scapy(); rng=random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]
    for i in range(count):
        # Deterministic RFC1918 sources only.
        src=f"10.20.{1+(i//250)%20}.{1+(i%250)}"; sport=rng.randint(1024,65535); dport=rng.choice([80,443,8080])
        p=Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="S",seq=rng.randint(0,2**32-1))
        p.time=(base+timedelta(seconds=i*0.001)).timestamp(); packets.append(p)
        labels.append(Label(_ts(base,i*0.001),"syn_flood","synthetic_syn_flood",f"SYN-{i:06d}",src,dst,"TCP",sport,dport,i,{"pattern":"high_syn_rate","ack_absent":True}).to_dict())
    return packets,labels

def udp_flood(count:int, seed:int, src="10.30.0.10", dst="10.30.1.20"):
    _require_scapy(); rng=random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]
    for i in range(count):
        sport=rng.randint(1024,65535); dport=rng.choice([53,123,1900,443]); size=rng.randint(200,1200)
        p=Ether()/IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/Raw(load=b"F"*size)
        p.time=(base+timedelta(seconds=i*0.0008)).timestamp(); packets.append(p)
        labels.append(Label(_ts(base,i*0.0008),"udp_flood","synthetic_udp_flood",f"UDP-{i:06d}",src,dst,"UDP",sport,dport,i,{"pattern":"high_packet_rate","payload_bytes":size}).to_dict())
    return packets,labels

def slow_http(sessions:int, seed:int, src="10.40.0.10", dst="10.40.1.20"):
    _require_scapy(); rng=random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]; idx=0
    for s in range(sessions):
        flow=f"SLOW-{s:05d}"; sport=35000+s; dport=80
        for frag in range(8):
            p=Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA")/Raw(load=b"GET /" if frag==0 else b"X")
            t=s*2.0+frag*1.5; p.time=(base+timedelta(seconds=t)).timestamp(); packets.append(p)
            labels.append(Label(_ts(base,t),"slow_http","slow_http_pattern",flow,src,dst,"TCP",sport,dport,idx,{"pattern":"small_fragments","long_iat":True} ).to_dict()); idx+=1
    return packets,labels

def _token(rng, n=24):
    raw=rng.randbytes(n)
    return base64.b32encode(raw).decode().rstrip("=").lower()

def dns_tunnel(queries:int, seed:int, src="10.50.0.10", dns="10.50.0.53"):
    _require_scapy(); rng=random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]
    domain="lab-tunnel.test"; idx=0
    for i in range(queries):
        label=_token(rng,rng.randint(12,24)); q=f"{label}.{domain}"; sport=40000+i; dport=53
        p=Ether()/IP(src=src,dst=dns)/UDP(sport=sport,dport=dport)/DNS(rd=1,qd=DNSQR(qname=q,qtype="A"))
        p.time=(base+timedelta(seconds=i*0.12)).timestamp(); packets.append(p)
        labels.append(Label(_ts(base,i*0.12),"dns_tunnel","synthetic_dns_tunnel",f"DNS-{i:06d}",src,dns,"DNS",sport,dport,i,{"domain":q,"long_label":len(label)>20,"lexical_anomaly":True}).to_dict()); idx+=1
    return packets,labels

def c2_beacon(beacons:int, seed:int, src="10.60.0.10", dst="10.60.1.20"):
    _require_scapy(); rng=random.Random(seed); base=datetime.now(timezone.utc); packets=[]; labels=[]
    interval=5.0
    for i in range(beacons):
        sport=45000; dport=443; jitter=rng.uniform(-0.15,0.15); t=i*interval+jitter
        p=Ether()/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA")/Raw(load=b"BEACON")
        p.time=(base+timedelta(seconds=t)).timestamp(); packets.append(p)
        labels.append(Label(_ts(base,t),"c2_beacon","synthetic_periodic_beacon",f"C2-{i:06d}",src,dst,"TCP",sport,dport,i,{"periodic_interval_s":interval,"jitter_s":jitter}).to_dict())
    return packets,labels

SCENARIOS={"benign":benign,"syn_flood":syn_flood,"udp_flood":udp_flood,"slow_http":slow_http,"dns_tunnel":dns_tunnel,"c2_beacon":c2_beacon}
