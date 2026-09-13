from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .models import PacketMetadata, FlowFeatures
from .utils import entropy, safe_rate, stable_flow_id, symmetry, burstiness

@dataclass
class FlowState:
    flow_id: str
    src_ip: str; dst_ip: str; src_port: int|None; dst_port: int|None; protocol: str
    start: float; last: float
    packets: int=0; bytes_total:int=0; fwd_packets:int=0; rev_packets:int=0
    fwd_bytes:int=0; rev_bytes:int=0
    packet_sizes:list[int]=field(default_factory=list)
    iats:list[float]=field(default_factory=list)
    src_ips:list[str]=field(default_factory=list); dst_ips:list[str]=field(default_factory=list)
    tls:dict=field(default_factory=dict); quic:dict=field(default_factory=dict)

class FlowAggregator:
    def __init__(self, timeout=60, max_sequence=5000):
        self.timeout=timeout; self.max_sequence=max_sequence; self.flows={}

    def _key(self,p): return (p.src_ip,p.src_port,p.dst_ip,p.dst_port,p.protocol)

    def add(self,p:PacketMetadata,source=None):
        key=self._key(p); rev=(p.dst_ip,p.dst_port,p.src_ip,p.src_port,p.protocol); now=p.timestamp
        if key not in self.flows and rev in self.flows:
            f=self.flows[rev]; direction='reverse'
        else:
            f=self.flows.get(key)
            if f is None:
                f=FlowState(flow_id=stable_flow_id(*key), src_ip=key[0], src_port=key[1], dst_ip=key[2], dst_port=key[3], protocol=key[4], start=now, last=now); self.flows[key]=f
            direction='forward'
        if f.packets>0: f.iats.append(max(0.0,now-f.last))
        f.last=now; f.packets+=1; f.bytes_total+=max(0,p.packet_length)
        f.packet_sizes.append(max(0,p.packet_length)); f.src_ips.append(p.src_ip); f.dst_ips.append(p.dst_ip)
        if direction=='forward': f.fwd_packets+=1; f.fwd_bytes+=max(0,p.packet_length)
        else: f.rev_packets+=1; f.rev_bytes+=max(0,p.packet_length)
        if p.tls: f.tls.update(p.tls)
        if p.quic: f.quic.update(p.quic)
        f.packet_sizes=f.packet_sizes[-self.max_sequence:]; f.iats=f.iats[-self.max_sequence:]
        f.src_ips=f.src_ips[-self.max_sequence:]; f.dst_ips=f.dst_ips[-self.max_sequence:]

    def finalize(self,source='pcap',force=False):
        now=max((f.last for f in self.flows.values()), default=0.0)
        out=[]; dead=[]
        for k,f in list(self.flows.items()):
            if force or now-f.last>=self.timeout:
                duration=max(0.0,f.last-f.start)
                out.append(FlowFeatures(
                    flow_id=f.flow_id,
                    timestamp_start=datetime.fromtimestamp(f.start,timezone.utc).isoformat(),
                    timestamp_end=datetime.fromtimestamp(f.last,timezone.utc).isoformat(),
                    duration_seconds=duration,src_ip=f.src_ip,dst_ip=f.dst_ip,src_port=f.src_port,dst_port=f.dst_port,
                    protocol=f.protocol,packets=f.packets,bytes_total=f.bytes_total,forward_packets=f.fwd_packets,
                    reverse_packets=f.rev_packets,forward_bytes=f.fwd_bytes,reverse_bytes=f.rev_bytes,
                    byte_packet_ratio=f.bytes_total/max(f.packets,1),directional_symmetry=symmetry(f.fwd_bytes,f.rev_bytes),
                    source_ip_entropy=entropy(f.src_ips),destination_ip_entropy=entropy(f.dst_ips),
                    unique_source_ips=len(set(f.src_ips)),unique_destination_ips=len(set(f.dst_ips)),
                    packet_rate=safe_rate(f.packets,duration),byte_rate=safe_rate(f.bytes_total,duration),
                    packet_sizes=f.packet_sizes,inter_arrival_times=f.iats,burstiness=burstiness(f.iats),
                    tls_metadata=f.tls,quic_metadata=f.quic,ingest_source=source or 'json'))
                dead.append(k)
        for k in dead: self.flows.pop(k,None)
        return out
