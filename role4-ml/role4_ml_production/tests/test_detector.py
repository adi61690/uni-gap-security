import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from role4_ml.detector import Role4Detector
from role4_ml.schemas import PredictRequest

def test_detector_dns():
    d=Role4Detector()
    r=d.predict(PredictRequest(type='dns', domain='x8f92kdl39qmx7z1p4k2.example.com', source_ip='10.0.0.1', destination_ip='8.8.8.8', destination_port=53, protocol='DNS', dns_query_rate=55))
    assert r.is_alert
    assert r.alert is not None
    assert r.alert.threat_class == 'DGA / DNS Tunneling'
    assert r.alert.security_context['metadata_only'] is True

def test_detector_encrypted():
    d=Role4Detector()
    sizes=[120,130,125,900,850,870,110,105,900,850,870,110]
    ts=[i*0.5 for i in range(len(sizes))]
    r=d.predict(PredictRequest(type='encrypted_session', packet_sizes=sizes, timestamps=ts, ja3='ja3_demo', ja4='ja4_demo', tls_version='TLS1.3', source_ip='10.0.0.1', destination_ip='172.16.4.8', destination_port=443, protocol='TCP'))
    assert r.is_alert
    assert r.alert is not None
    assert r.alert.model.sequence_model_used in (True, False)
