from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
manifest=json.loads((ROOT/'data/manifests/lab_generated_unidirectional_v1.json').read_text())
assert manifest['rows']==7000
assert set(manifest['classes'])=={'BENIGN','SYN_FLOOD','UDP_FLOOD','SLOW_HTTP','DNS_TUNNEL','DGA','C2_BEACON'}
assert (ROOT/'frontend/uni-gap-security/package.json').exists()
assert (ROOT/'.github/workflows/validate.yml').exists()
print('repository validation OK')
