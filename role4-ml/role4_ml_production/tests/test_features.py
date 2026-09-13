import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from role4_ml.features import dns_feature_vector, encrypted_feature_vector, periodicity_features, sequence_matrix

def test_dns_features():
    f=dns_feature_vector('x8f92kdl39qmx7z1p4k2.example.com')
    assert f['dns_query_length'] > 0
    assert f['dns_entropy'] > 0

def test_encrypted_features():
    f=encrypted_feature_vector([120,130,900,850,120,130],[0,.5,1,1.5,2,2.5], 'ja3','ja4')
    assert f['packet_count'] == 6
    assert 0 <= f['periodicity_score'] <= 1
    assert f['iat_cv'] >= 0

def test_sequence_shape():
    x=sequence_matrix([100,200,300],[0,.2,.5])
    assert x.shape == (64,2)
