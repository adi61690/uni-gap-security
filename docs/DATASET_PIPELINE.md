# Dataset Pipeline

```text
Lab traffic generation
        ↓
PCAP capture / labeled scenario
        ↓
Role 2 passive ingestion
        ↓
Unidirectional flow construction
        ↓
Feature extraction
        ↓
`data/processed/lab_generated_unidirectional_flows.csv`
        ↓
Role 3 + Role 4 model training
        ↓
Backend inference + WebSocket alerts
        ↓
Role 6 dashboard
```

The flow key is source → destination + protocol + source/destination ports. Reverse packets are not merged into the same record.
