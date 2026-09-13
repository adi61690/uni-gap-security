from __future__ import annotations
import time
from .schemas import FlowFeatures, Alert
from .sequence_model import load_lstm, predict_lstm
from .models import Role3Models

LABELS=['DDoS','Botnet C2','Recon / Port Scan','Data Exfiltration']
SUBTYPES={'DDoS':'Volumetric anomaly','Botnet C2':'Periodic beaconing','Recon / Port Scan':'Fan-out / scan anomaly','Data Exfiltration':'Asymmetric outbound transfer'}
EXPLANATIONS={
'DDoS':'Traffic volume or source/destination concentration is significantly outside the learned baseline.',
'Botnet C2':'Repeated timing structure and inter-arrival behavior differ from the learned baseline.',
'Recon / Port Scan':'Destination fan-out or scan rate is significantly outside the learned baseline.',
'Data Exfiltration':'Outbound volume or flow asymmetry is significantly outside the learned baseline.'}

def severity(conf, anomaly):
    x=max(conf, anomaly)
    return 'Critical' if x>=.97 else 'High' if x>=.90 else 'Medium' if x>=.78 else 'Low'

class Detector:
    def __init__(self, models=None):
        self.models=models or Role3Models()
        self.lstm=load_lstm()
    def predict(self,f:FlowFeatures):
        t=time.perf_counter(); r=self.models.predict(f); pred=r['predicted']; conf=r['confidence']; anomaly=r['anomaly_score']; d=r['features']
        if anomaly < 0.52 and conf < 0.97:
            pred = None
        # transparent rule-to-model guardrails add evidence but never perform active action
        lstm_score=predict_lstm(self.lstm, f.inter_arrival_times)
        periodic=max(d['periodicity_score'], d['autocorrelation_peak'], lstm_score)
        if pred=='Botnet C2' and periodic<.18 and conf<.92: pred=None
        if pred=='DDoS' and d['packet_rate']<200 and conf<.9: pred=None
        if pred=='Recon / Port Scan' and d['fanout']<5 and conf<.9: pred=None
        if pred=='Data Exfiltration' and d['outbound_inbound_ratio']<2 and conf<.9: pred=None
        latency=(time.perf_counter()-t)*1000
        if not pred:
            return {'is_alert':False,'observation':{'anomaly_score':anomaly,'class_scores':r['class_scores'],'features':d}}
        evidence={'anomaly_score':anomaly,'packet_rate':d['packet_rate'],'source_ip_entropy':d['source_ip_entropy'],'destination_ip_entropy':d['destination_ip_entropy'],'amplification_factor':d['amplification_factor'],'fanout':d['fanout'],'unique_destination_hosts':d['unique_destination_hosts'],'scan_rate':d['scan_rate'],'beacon_interval':d['iat_mean'],'iat_cv':d['iat_cv'],'periodicity_score':d['periodicity_score'],'lstm_beacon_score':lstm_score,'dominant_frequency_hz':d['dominant_frequency_hz'],'fft_magnitude':d['fft_magnitude'],'autocorrelation_peak':d['autocorrelation_peak'],'outbound_bytes':d['outbound_bytes'],'inbound_bytes':d['inbound_bytes'],'outbound_inbound_ratio':d['outbound_inbound_ratio'],'flow_duration':d['flow_duration'],'volume_asymmetry':d['volume_asymmetry'],'feature_values':d,'explanation':EXPLANATIONS[pred]}
        alert=Alert(timestamp=f.timestamp_end,flow_id=f.flow_id,threat_class=pred,threat_subtype=SUBTYPES[pred],severity=severity(conf,anomaly),confidence=min(1,max(conf,anomaly*.85)),source_ip=f.src_ip,destination_ip=f.dst_ip,destination_port=int(f.dst_port or 0),protocol=f.protocol,evidence=evidence,model={'name':f'role3_{pred.lower().replace(" ","_").replace("/","_")}','version':'role3.0.0','latency_ms':latency,'class_scores':r['class_scores'],'model_type':'XGBoost + Isolation Forest' if self.models.classifier else 'Heuristic','sequence_model_used': bool(self.lstm and pred=='Botnet C2')},evidence_summary=EXPLANATIONS[pred])
        return {'is_alert':True,'alert':alert.model_dump(),'observation':{'class_scores':r['class_scores'],'features':d}}
