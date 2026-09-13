from __future__ import annotations
import struct
from typing import Any
from .models import PacketMetadata
from .utils import normalize_protocol

# Minimal, dependency-free decoders for NetFlow v5 and a template-driven subset of IPFIX.
# All outputs are header/flow metadata; no payload bytes are retained.

def decode_netflow_v5(data: bytes) -> list[PacketMetadata]:
    if len(data)<24: return []
    version,count=struct.unpack('!HH',data[:4])
    if version!=5: return []
    sys_uptime, unix_secs, unix_nsecs = struct.unpack('!III', data[4:16])
    out=[]; offset=24; rec_len=48
    for i in range(min(count,(len(data)-offset)//rec_len)):
        r=data[offset+i*rec_len:offset+(i+1)*rec_len]
        if len(r)<rec_len: break
        src=r[0:4]; dst=r[4:8]; next_hop=r[8:12]
        src_ip='.'.join(map(str,src)); dst_ip='.'.join(map(str,dst))
        src_port,dst_port=struct.unpack('!HH',r[32:36]); packets,bytes_total=struct.unpack('!II',r[16:24])
        first,last=struct.unpack('!II',r[24:32]); proto=r[38]
        # NetFlow v5 timestamps are exporter uptime milliseconds; map first-seen uptime to epoch.
        ts=(unix_secs + unix_nsecs/1_000_000_000.0) - max(0, sys_uptime-first)/1000.0
        out.append(PacketMetadata(timestamp=ts,src_ip=src_ip,dst_ip=dst_ip,src_port=src_port,dst_port=dst_port,protocol=normalize_protocol(str(proto),src_port,dst_port),packet_length=max(bytes_total,packets),input_source='netflow'))
    return out

def decode_normalized_json(record: dict[str,Any], source='netflow') -> PacketMetadata:
    proto=normalize_protocol(str(record.get('protocol') or record.get('proto') or 'OTHER'), record.get('src_port') or record.get('sport'), record.get('dst_port') or record.get('dport'))
    return PacketMetadata(timestamp=float(record.get('timestamp') or record.get('ts') or 0),src_ip=str(record.get('src_ip') or record.get('source_ip')),dst_ip=str(record.get('dst_ip') or record.get('destination_ip')),src_port=record.get('src_port') or record.get('sport'),dst_port=record.get('dst_port') or record.get('dport'),protocol=proto,packet_length=int(record.get('packet_length') or record.get('bytes') or 0),input_source=source)
