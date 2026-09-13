from __future__ import annotations
import math
import numpy as np
from .schemas import FlowFeatures

def _stats(a):
    x=np.asarray(a,dtype=float)
    if x.size==0: return {'count':0,'mean':0.0,'std':0.0,'min':0.0,'max':0.0,'p50':0.0,'p95':0.0}
    return {'count':float(x.size),'mean':float(x.mean()),'std':float(x.std()),'min':float(x.min()),'max':float(x.max()),'p50':float(np.percentile(x,50)),'p95':float(np.percentile(x,95))}

def fft_features(values):
    x=np.asarray(values,dtype=float)
    if x.size<4: return {'dominant_frequency_hz':0.0,'fft_magnitude':0.0,'periodicity_score':0.0}
    x=x-x.mean(); spec=np.abs(np.fft.rfft(x)); spec[0]=0
    idx=int(np.argmax(spec)); mag=float(spec[idx]); score=float(mag/(spec.sum()+1e-9))
    return {'dominant_frequency_hz':float(idx/max(x.size,1)),'fft_magnitude':mag,'periodicity_score':min(1.0,score*4)}

def autocorr(values):
    x=np.asarray(values,dtype=float)
    if x.size<4 or np.std(x)==0: return 0.0
    x=x-x.mean(); c=np.correlate(x,x,mode='full')[x.size-1:]; c=c/(c[0]+1e-9)
    return float(np.max(c[1:min(len(c),max(3,x.size//2))])) if len(c)>1 else 0.0

def iat_metrics(iats):
    x=np.asarray(iats,dtype=float)
    mean=float(x.mean()) if x.size else 0.0
    return mean, float(x.std()/mean) if x.size and mean>1e-9 else 0.0

def derive_features(f: FlowFeatures) -> dict[str,float]:
    iat_mean, iat_cv=iat_metrics(f.inter_arrival_times)
    fft=fft_features(f.inter_arrival_times)
    amp=float(f.forward_bytes/max(f.reverse_bytes,1)) if f.reverse_bytes else float(f.forward_bytes)
    volume_asym=abs(f.forward_bytes-f.reverse_bytes)/max(f.forward_bytes+f.reverse_bytes,1)
    fanout=max(int(f.unique_destination_ips),1)
    scan_rate=fanout/max(f.duration_seconds,1e-3)
    return {
        'duration_seconds':f.duration_seconds,'packets':f.packets,'bytes_total':f.bytes_total,
        'forward_packets':f.forward_packets,'reverse_packets':f.reverse_packets,
        'forward_bytes':f.forward_bytes,'reverse_bytes':f.reverse_bytes,
        'byte_packet_ratio':f.byte_packet_ratio,'directional_symmetry':f.directional_symmetry,
        'source_ip_entropy':f.source_ip_entropy,'destination_ip_entropy':f.destination_ip_entropy,
        'unique_source_ips':f.unique_source_ips,'unique_destination_ips':f.unique_destination_ips,
        'packet_rate':f.packet_rate,'byte_rate':f.byte_rate,'burstiness':f.burstiness,
        'iat_mean':iat_mean,'iat_cv':iat_cv,'autocorrelation_peak':autocorr(f.inter_arrival_times),
        'dominant_frequency_hz':fft['dominant_frequency_hz'],'fft_magnitude':fft['fft_magnitude'],
        'periodicity_score':fft['periodicity_score'],'amplification_factor':amp,
        'fanout':fanout,'unique_destination_hosts':fanout,'scan_rate':scan_rate,
        'outbound_bytes':float(f.forward_bytes),'inbound_bytes':float(f.reverse_bytes),
        'outbound_inbound_ratio':amp,'flow_duration':f.duration_seconds,'volume_asymmetry':volume_asym,
        'packet_mean':_stats(f.packet_sizes)['mean'],'packet_p95':_stats(f.packet_sizes)['p95'],
    }
