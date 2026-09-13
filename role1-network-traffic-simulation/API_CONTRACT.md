# Role 1 Dataset Contract

Role 1 emits **offline labeled traffic datasets**, not frontend/API alerts.

## PCAP

`data/pcap/*.pcap` contains the generated traffic patterns for Role 2.

## JSONL labels

Each line:

```json
{
  "timestamp":"2026-09-11T10:00:00+00:00",
  "scenario":"c2_beacon",
  "label":"synthetic_periodic_beacon",
  "flow_id":"C2-000001",
  "source_ip":"10.60.0.10",
  "destination_ip":"10.60.1.20",
  "protocol":"TCP",
  "source_port":45000,
  "destination_port":443,
  "packet_index":1,
  "features_hint": {
    "periodic_interval_s":5.0,
    "jitter_s":0.02
  }
}
```

Role 2 should parse the PCAP and derive actual features from observed packets. The `features_hint` field is for ground-truth dataset labeling and should not be used as an observed feature in production inference.
