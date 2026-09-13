# Role 2 API Contract

Base URL: `http://localhost:8100`

## Health
`GET /health`

Returns passive-security flags and the configured Role 4 service URL.

## PCAP / PCAPNG
`POST /ingest/pcap`
```json
{"path":"C:/captures/sample.pcapng","max_packets":100000}
```

`POST /ingest/upload` multipart form-data field `file` for `.pcap`, `.pcapng`, or `.cap`.

## Zeek JSON
`POST /ingest/zeek`
```json
{"path":"C:/zeek/flows.json"}
```

## NetFlow/IPFIX/sFlow integration
`POST /ingest/flow-record` accepts normalized exporter records. A passive UDP listener foundation is available in `DatagramFlowListener`; NetFlow v5 is decoded without retaining payload. For IPFIX/sFlow, feed records from a validated exporter/collector/template decoder into `ingest_flow_record` rather than guessing binary layouts.

## Role 4 handoff
`POST /role4/predict` forwards normalized metadata to the external Role 4 ML service defined by `ROLE4_SERVICE_URL`.

Role 2 emits `role2.v2` `FlowFeatures` with:
- flow IDs, timestamps, addresses, ports, protocol
- packet/byte totals
- forward/reverse counts and bytes
- byte/packet ratio
- directional symmetry
- source/destination IP entropy
- packet and byte rates
- packet-size sequence
- IAT sequence and burstiness
- TLS metadata (JA3/JA3S/JA4 when available)
- QUIC metadata

**No application payload bytes are emitted, stored, forwarded, or persisted.** TLS/QUIC parsing is limited to handshake/metadata inspection; payload decryption is not performed.
