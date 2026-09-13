# Uni-Gap Security — Architecture

## Data ownership

| Layer | Owns |
|---|---|
| Role 1 | lab traffic generation, raw PCAP, ground-truth labels |
| Role 2 | packet/flow metadata and normalized feature extraction |
| Role 3 | DDoS/C2/recon/exfil models |
| Role 4 | DGA/DNS/encrypted-session models |
| Backend | auth, persistence, orchestration, alerts, reports, audit |
| Frontend | analyst interaction and visualization only |

## Dataset handoff

```text
Role 1 PCAP
  -> Role 2
     -> role2.v2 FlowFeatures
        -> data/processed/flow_features.csv
        -> Backend /api/v1/ingest/flow
           -> Role 3 + Role 4
              -> standardized alert
                 -> Backend DB + WebSocket
                    -> Frontend
```

## Threat ownership

- Role 3: DDoS / volumetric, C2 beaconing, recon / port scan, data exfiltration.
- Role 4: DGA / DNS tunneling and encrypted-session malware / sequence evidence.

Both ML services share the same frontend-compatible `Alert` shape.
