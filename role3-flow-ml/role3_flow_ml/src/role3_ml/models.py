from __future__ import annotations
import os, json, time
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE=True
except Exception:
    XGBClassifier=None; XGB_AVAILABLE=False
from .features import derive_features
from .schemas import FlowFeatures

FEATURES=['duration_seconds','packets','bytes_total','byte_packet_ratio','directional_symmetry','source_ip_entropy','destination_ip_entropy','unique_source_ips','unique_destination_ips','packet_rate','byte_rate','burstiness','iat_mean','iat_cv','autocorrelation_peak','dominant_frequency_hz','periodicity_score','amplification_factor','fanout','scan_rate','outbound_inbound_ratio','volume_asymmetry']
MODEL_VERSION='role3.0.0'

def vector(f):
    d=derive_features(f); return np.array([d.get(k,0.0) for k in FEATURES],dtype=float)

class Role3Models:
    def __init__(self, model_dir='models'):
        self.model_dir=Path(model_dir); self.model_dir.mkdir(parents=True, exist_ok=True)
        self.classifier=None; self.iso=None; self.scaler=None; self.baseline={}
        self.load()
    def load(self):
        cp=self.model_dir/'xgb_multiclass.joblib'; ip=self.model_dir/'isolation_forest.joblib'; bp=self.model_dir/'baseline_profile.json'
        if cp.exists(): self.classifier=joblib.load(cp)
        if ip.exists(): self.iso=joblib.load(ip)
        if bp.exists(): self.baseline=json.loads(bp.read_text())
    def save(self):
        if self.classifier: joblib.dump(self.classifier,self.model_dir/'xgb_multiclass.joblib')
        if self.iso: joblib.dump(self.iso,self.model_dir/'isolation_forest.joblib')
        (self.model_dir/'baseline_profile.json').write_text(json.dumps(self.baseline,indent=2))
    def train(self, X,y):
        if XGB_AVAILABLE:
            self.classifier=XGBClassifier(n_estimators=180,max_depth=5,learning_rate=.08,subsample=.9,colsample_bytree=.9,objective='multi:softprob',eval_metric='mlogloss',num_class=4,tree_method='hist',random_state=42)
        else:
            from sklearn.ensemble import HistGradientBoostingClassifier
            self.classifier=HistGradientBoostingClassifier(max_iter=180,max_leaf_nodes=31,learning_rate=.08,random_state=42)
        self.classifier.fit(X,y)
        self.iso=Pipeline([('scale',StandardScaler()),('iso',IsolationForest(n_estimators=200,contamination=.04,random_state=42))])
        self.iso.fit(X)
        self.baseline={k:{'p05':float(np.percentile(X[:,i],5)),'p95':float(np.percentile(X[:,i],95))} for i,k in enumerate(FEATURES)}
        self.save()
    def predict(self,f):
        x=vector(f).reshape(1,-1); d=derive_features(f)
        if self.classifier is None: return {'class_scores':{},'predicted':None,'confidence':0.0,'anomaly_score':0.0,'features':d}
        probs=self.classifier.predict_proba(x)[0]; labels=list(self.classifier.classes_); idx=int(np.argmax(probs))
        names=['DDoS','Botnet C2','Recon / Port Scan','Data Exfiltration']
        def name_for(value):
            try:
                iv=int(value)
                return names[iv] if 0 <= iv < len(names) else str(value)
            except Exception:
                return str(value)
        scores={name_for(labels[i]):float(probs[i]) for i in range(len(labels))}
        conf=float(probs[idx]); pred=name_for(labels[idx])
        iso_raw=float(-self.iso.decision_function(x)[0]) if self.iso else 0.0
        anomaly=float(1/(1+np.exp(-4*iso_raw)))
        return {'class_scores':scores,'predicted':pred,'confidence':conf,'anomaly_score':anomaly,'features':d}
