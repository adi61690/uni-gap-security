import pytest
try:
    import scapy  # noqa: F401
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not installed in this environment")

from app.scenarios import benign, syn_flood, udp_flood, slow_http, dns_tunnel, c2_beacon

@pytest.mark.parametrize("fn,kwargs", [
    (benign,{"count":5}),
    (syn_flood,{"count":5}),
    (udp_flood,{"count":5}),
    (slow_http,{"sessions":1}),
    (dns_tunnel,{"queries":5}),
    (c2_beacon,{"beacons":5}),
])
def test_scenario(fn,kwargs):
    p,l=fn(seed=42,**kwargs)
    assert p and l and len(p)==len(l)
