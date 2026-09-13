import argparse, csv, json, time, urllib.request, urllib.error
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--csv',default='data/processed/lab_generated_unidirectional_flows.csv'); ap.add_argument('--backend',default='http://localhost:8000'); ap.add_argument('--limit',type=int,default=100); ap.add_argument('--delay',type=float,default=.03); args=ap.parse_args()
    url=args.backend.rstrip('/')+'/api/v1/ingest/flow'
    rows=list(csv.DictReader(open(args.csv,encoding='utf-8')))[:args.limit]
    for r in rows:
        # Role 2/ML services only need the normalized fields; keep original lab columns as extra metadata.
        duration=float(r.get('flow_duration') or 0); packets=int(float(r.get('total_packets') or 0)); total=int(float(r.get('total_bytes') or 0));
        payload={"schema_version":"role2.v2","flow_id":r['flow_id'],"timestamp_start":r['timestamp'],"timestamp_end":r['timestamp'],"duration_seconds":duration,"src_ip":r['src_ip'],"dst_ip":r['dst_ip'],"src_port":int(r['src_port']),"dst_port":int(r['dst_port']),"protocol":r['protocol'],"packets":packets,"bytes_total":total,"forward_packets":packets,"reverse_packets":int(r.get('backward_packets') or 0),"forward_bytes":int(r.get('outbound_bytes') or total),"reverse_bytes":int(r.get('inbound_bytes') or 0),"byte_packet_ratio":float(total/max(packets,1)),"directional_symmetry":float(min(int(r.get('inbound_bytes') or 0),int(r.get('outbound_bytes') or total))/max(int(r.get('outbound_bytes') or total),1)),"source_ip_entropy":float(r.get('source_ip_entropy') or 0),"destination_ip_entropy":float(r.get('destination_ip_entropy') or 0),"unique_source_ips":1,"unique_destination_ips":int(r.get('unique_destination_hosts') or 1),"packet_rate":float(r.get('packet_rate') or 0),"byte_rate":float(r.get('byte_rate') or 0),"packet_sizes":[int(float(r.get('packet_size_mean') or 0))]*min(packets,64),"inter_arrival_times":[float(r.get('inter_arrival_time') or 0)]*min(packets,64),"burstiness":float(r.get('volume_asymmetry') or 0),"tls_metadata":{"ja3":r.get('ja3',''),'ja4':r.get('ja4',''),'version':r.get('tls_version','')},"quic_metadata":{"version":r.get('quic_version','')},"ingest_source":"lab_dataset"}
        req=urllib.request.Request(url,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        try:
            with urllib.request.urlopen(req,timeout=10) as resp: print(resp.status,resp.read().decode()[:240])
        except urllib.error.HTTPError as e: print('HTTP',e.code,e.read().decode()[:300])
        except Exception as e: print('ERROR',e)
        time.sleep(args.delay)
if __name__=='__main__': main()
