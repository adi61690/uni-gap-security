from __future__ import annotations
from pathlib import Path
import json, random
import numpy as np
from .models import Role3Models, FEATURES

def make_rows(n_per=500, seed=42):
    rng=random.Random(seed); X=[]; y=[]
    for label in range(4):
      for _ in range(n_per):
        base=dict(duration_seconds=rng.uniform(.1,60),packets=rng.randint(5,1000),bytes_total=rng.randint(500,500000),byte_packet_ratio=rng.uniform(50,1200),directional_symmetry=rng.uniform(.2,1),source_ip_entropy=rng.uniform(2,7),destination_ip_entropy=rng.uniform(2,7),unique_source_ips=rng.randint(1,20),unique_destination_ips=rng.randint(1,40),packet_rate=rng.uniform(1,150),byte_rate=rng.uniform(100,500000),burstiness=rng.uniform(.1,1),iat_mean=rng.uniform(.01,2),iat_cv=rng.uniform(.05,1.5),autocorrelation_peak=rng.uniform(.05,.8),dominant_frequency_hz=rng.uniform(.01,2),periodicity_score=rng.uniform(.05,.9),amplification_factor=rng.uniform(.5,5),fanout=rng.randint(1,40),scan_rate=rng.uniform(.1,20),outbound_inbound_ratio=rng.uniform(.2,5),volume_asymmetry=rng.uniform(.05,1))
        if label==0: base.update(packet_rate=rng.uniform(300,3000),source_ip_entropy=rng.uniform(6,10),fanout=rng.randint(20,300),amplification_factor=rng.uniform(3,20))
        elif label==1: base.update(iat_cv=rng.uniform(.01,.2),autocorrelation_peak=rng.uniform(.55,.98),periodicity_score=rng.uniform(.55,.98),dominant_frequency_hz=rng.uniform(.05,3))
        elif label==2: base.update(fanout=rng.randint(30,500),unique_destination_ips=rng.randint(30,500),scan_rate=rng.uniform(10,100))
        else: base.update(outbound_inbound_ratio=rng.uniform(3,20),volume_asymmetry=rng.uniform(.65,.99),outbound_bytes=rng.uniform(100000,20000000) if 'outbound_bytes' in base else 0)
        X.append([base[k] for k in FEATURES]); y.append(label)
    return np.asarray(X,float),np.asarray(y,int)

def train(model_dir='models'):
    X,y=make_rows(); m=Role3Models(model_dir); m.train(X,y)
    Path(model_dir,'training_manifest.json').write_text(json.dumps({'version':'role3.0.0','samples':len(y),'features':FEATURES,'labels':['DDoS','Botnet C2','Recon / Port Scan','Data Exfiltration']},indent=2))
    return m
