from __future__ import annotations
import argparse, json, yaml
from pathlib import Path
from .scenarios import SCENARIOS
from .dataset import write_pcap, write_jsonl, write_manifest

def main():
    ap=argparse.ArgumentParser(description="Uni-Gap Role 1 lab traffic generator")
    sub=ap.add_subparsers(dest="cmd",required=True)
    d=sub.add_parser("dataset"); d.add_argument("--config",required=True)
    args=ap.parse_args()
    if args.cmd=="dataset":
        cfg=yaml.safe_load(Path(args.config).read_text())
        seed=int(cfg.get("seed",42)); limits=cfg.get("limits",{}); max_total=int(limits.get("max_packets_total",5000)); max_per=int(limits.get("max_packets_per_scenario",1000))
        packets=[]; labels=[]; counts={}
        for name, params in cfg.get("scenarios",{}).items():
            if name not in SCENARIOS: raise SystemExit(f"unknown scenario: {name}")
            fn=SCENARIOS[name]; requested=int(params.get("packets", params.get("queries", params.get("beacons", params.get("sessions",0)))))
            if name=="slow_http": kwargs={"sessions":min(requested,max_per)}
            elif name=="dns_tunnel": kwargs={"queries":min(requested,max_per)}
            elif name=="c2_beacon": kwargs={"beacons":min(requested,max_per)}
            else: kwargs={"count":min(requested,max_per)}
            p,l=fn(seed=seed,**kwargs); remaining=max_total-len(packets)
            packets.extend(p[:remaining]); labels.extend(l[:remaining]); counts[name]=min(len(p),remaining)
            if len(packets)>=max_total: break
        write_pcap(packets,cfg["output"]["pcap"])
        n=write_jsonl(labels,cfg["output"]["labels"])
        manifest={"schema":"role1.v1","seed":seed,"packet_count":len(packets),"label_count":n,"scenarios":counts,"outputs":cfg["output"],"lab_only":True}
        write_manifest(cfg["output"]["manifest"],manifest)
        print(json.dumps(manifest,indent=2))

if __name__=="__main__": main()
