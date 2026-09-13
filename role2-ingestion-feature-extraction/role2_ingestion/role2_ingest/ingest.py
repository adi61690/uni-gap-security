from __future__ import annotations
import json, os, threading, time
from pathlib import Path
from typing import Callable, Iterable
from .models import PacketMetadata, FlowFeatures
from .flows import FlowAggregator
from .tls import parse_tls_handshake
from .quic import summarize_quic
from .utils import normalize_protocol
from .netflow import decode_netflow_v5, decode_normalized_json

class IngestionEngine:
    def __init__(self, timeout=60, export_path=None, on_flow: Callable[[FlowFeatures],None]|None=None):
        self.agg=FlowAggregator(timeout=timeout)
        self.export_path=Path(export_path) if export_path else None
        self.on_flow=on_flow
        if self.export_path: self.export_path.parent.mkdir(parents=True,exist_ok=True)
    def _emit(self, flow: FlowFeatures):
        if self.export_path:
            with self.export_path.open('a',encoding='utf-8') as f: f.write(json.dumps(flow.model_dump(),separators=(',',':'))+'\n')
        if self.on_flow: self.on_flow(flow)
    def ingest_packet(self,p:PacketMetadata,source=None): self.agg.add(p,source or p.input_source)
    def flush(self,source='pcap',force=True):
        flows=self.agg.finalize(source,force=force)
        for f in flows: self._emit(f)
        return flows

    def ingest_pcap(self,path,max_packets=None):
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
        count=0
        for pkt in PcapReader(str(path)):
            if max_packets and count>=max_packets: break
            count+=1; ts=float(getattr(pkt,'time',time.time()))
            if IP in pkt: src,dst=pkt[IP].src,pkt[IP].dst
            elif IPv6 in pkt: src,dst=pkt[IPv6].src,pkt[IPv6].dst
            else: continue
            sport=dport=None; proto='OTHER'; tls={}; quic={}; tcp_flags=None
            if TCP in pkt:
                sport,dport=int(pkt[TCP].sport),int(pkt[TCP].dport); proto='TCP'; tcp_flags=str(pkt[TCP].flags)
                # Inspect bounded TLS handshake bytes only; never keep payload.
                if sport in {443,8443} or dport in {443,8443}:
                    b=bytes(pkt[TCP].payload)[:16384]
                    tls=parse_tls_handshake(b)
            elif UDP in pkt:
                sport,dport=int(pkt[UDP].sport),int(pkt[UDP].dport); proto='UDP'
                if sport in {443,784} or dport in {443,784}:
                    b=bytes(pkt[UDP].payload)[:8]
                    quic=summarize_quic(len(pkt[UDP].payload),b[0] if b else None)
            elif ICMP in pkt: proto='ICMP'
            proto=normalize_protocol(proto,sport,dport)
            p=PacketMetadata(timestamp=ts,src_ip=src,dst_ip=dst,src_port=sport,dst_port=dport,protocol=proto,packet_length=len(pkt),tcp_flags=tcp_flags,tls=tls,quic=quic,input_source='pcap')
            self.ingest_packet(p,'pcap')
        return self.flush('pcap',True)

    def ingest_zeek_json(self,path):
        for line in open(path,encoding='utf-8'):
            if not line.strip(): continue
            d=json.loads(line)
            src=d.get('id.orig_h') or d.get('src_ip'); dst=d.get('id.resp_h') or d.get('dst_ip')
            if not src or not dst: continue
            ts=d.get('ts',time.time())
            if isinstance(ts,str):
                from datetime import datetime
                try: ts=datetime.fromisoformat(ts.replace('Z','+00:00')).timestamp()
                except Exception: ts=time.time()
            src_port=d.get('id.orig_p') or d.get('src_port'); dst_port=d.get('id.resp_p') or d.get('dst_port')
            proto=normalize_protocol(str(d.get('proto','OTHER')),src_port,dst_port)
            tls={k:d[k] for k in ('ja3','ja3s','ja4','ssl_version','cipher','server_name','alpn') if k in d}
            quic={k:d[k] for k in ('version','server_name','ja4') if k in d}
            size=int(d.get('orig_bytes') or d.get('resp_bytes') or d.get('bytes') or 0)
            self.ingest_packet(PacketMetadata(timestamp=float(ts),src_ip=src,dst_ip=dst,src_port=src_port,dst_port=dst_port,protocol=proto,packet_length=size,tls=tls,quic=quic,input_source='zeek'),'zeek')
        return self.flush('zeek',True)

    def ingest_flow_record(self, record:dict, source='netflow'):
        p=decode_normalized_json(record,source); self.ingest_packet(p,source)
        return self.flush(source,True)

class DatagramFlowListener:
    def __init__(self,engine:IngestionEngine,host='0.0.0.0',port=2055,source='netflow',on_packet=None):
        import socket
        self.engine=engine; self.host=host; self.port=port; self.source=source; self.sock=None; self.stop_event=threading.Event(); self.on_packet=on_packet
    def start_background(self):
        t=threading.Thread(target=self.run,daemon=True); t.start(); return t
    def run(self):
        import socket
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.sock.bind((self.host,self.port))
        while not self.stop_event.is_set():
            self.sock.settimeout(1)
            try: data,addr=self.sock.recvfrom(65535)
            except socket.timeout: continue
            self.handle_datagram(data,addr)
    def handle_datagram(self,data,addr):
        packets=[]
        if self.source=='netflow' and data[:2]==b'\x00\x05': packets=decode_netflow_v5(data)
        for p in packets: self.engine.ingest_packet(p,self.source)
        flows=self.engine.flush(self.source,True) if packets else []
        if self.on_packet: self.on_packet({'source':self.source,'sender':addr,'bytes':len(data),'decoded_records':len(packets),'flows':len(flows)})
        return {'received_bytes':len(data),'decoded_records':len(packets),'flows':len(flows)}
    def stop(self):
        self.stop_event.set()
        if self.sock:
            try:self.sock.close()
            except Exception:pass
