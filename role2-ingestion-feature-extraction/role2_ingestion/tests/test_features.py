from role2_ingest.flows import FlowAggregator
from role2_ingest.models import PacketMetadata

def pkt(ts,src,dst,sport,dport,size,proto='TCP'):
    return PacketMetadata(timestamp=ts,src_ip=src,dst_ip=dst,src_port=sport,dst_port=dport,protocol=proto,packet_length=size)

def test_bidirectional_features():
    a=FlowAggregator(timeout=60)
    a.add(pkt(1,'10.0.0.1','10.0.0.2',1234,443,100)); a.add(pkt(1.2,'10.0.0.2','10.0.0.1',443,1234,200)); a.add(pkt(1.5,'10.0.0.1','10.0.0.2',1234,443,300))
    out=a.finalize('pcap',True); f=out[0]
    assert f.packets==3; assert f.forward_packets==2; assert f.reverse_packets==1
    assert f.bytes_total==600; assert f.directional_symmetry > 0; assert len(f.inter_arrival_times)==2
    assert f.passive_guardrails['payload_persistence'] is False

def test_zeek_passthrough(tmp_path):
    p=tmp_path/'zeek.json'; p.write_text('{"ts":"2026-09-11T10:00:00Z","id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","id.orig_p":1234,"id.resp_p":443,"proto":"tcp","ja3":"abc","ja4":"t13d"}\n')
    from role2_ingest.ingest import IngestionEngine
    out=IngestionEngine().ingest_zeek_json(str(p)); assert out[0].tls_metadata['ja3']=='abc'; assert out[0].tls_metadata['ja4']=='t13d'
