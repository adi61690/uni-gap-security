import sys
sys.path.insert(0,'src')
from role3_ml.schemas import FlowFeatures
from role3_ml.features import derive_features

def test_derived_metrics():
    f=FlowFeatures(flow_id='x',timestamp_start='a',timestamp_end='b',duration_seconds=2,src_ip='1',dst_ip='2',packets=10,bytes_total=1000,forward_packets=8,reverse_packets=2,forward_bytes=800,reverse_bytes=200,byte_packet_ratio=100,directional_symmetry=.25,source_ip_entropy=4,destination_ip_entropy=3,unique_source_ips=2,unique_destination_ips=5,packet_rate=5,byte_rate=500,packet_sizes=[100,110,90,120],inter_arrival_times=[.1,.1,.2,.1],burstiness=.2)
    d=derive_features(f)
    assert d['outbound_inbound_ratio']==4
    assert d['fanout']==5

def test_role2_schema_is_accepted():
    f=FlowFeatures(flow_id='flow',timestamp_start='2026-09-11T00:00:00Z',timestamp_end='2026-09-11T00:00:01Z',src_ip='10.0.0.1',dst_ip='10.0.0.2')
    assert f.schema_version=='role2.v2'
