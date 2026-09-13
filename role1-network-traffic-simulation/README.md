# Role 1 — Network & Traffic Simulation Engineer

## Uni-Gap Security Lab Traffic Generator

Role 1 is a **lab-only traffic generation and testbed package** for the Uni-Gap Security pipeline.

It generates labeled benign and adversarial *simulation datasets* for:

- benign TCP/UDP baseline traffic
- SYN-flood-like packet patterns
- UDP-flood-like packet patterns
- slow-HTTP exhaustion *pattern simulation*
- DNS tunneling-like lexical patterns
- C2 beaconing / periodic timing patterns

It also provides:

- PCAP/PCAPNG dataset generation using Scapy when available
- iperf3/Trex/Ostinato adapter stubs for external traffic engines
- Linux network-namespace lab topology scripts
- one-way/data-diode validation checks
- dataset manifest + labels aligned to Role 2
- scenario configuration files
- deterministic seeded generation for reproducibility
- safety guardrails: private targets only, bounded packet counts/rates, and explicit lab mode

## Architecture

```text
Role 1
  |
  +--> benign / scenario traffic generation
  |
  +--> PCAP + labels + manifest
  v
Role 2 — Ingestion & Feature Extraction
  |
  v
Role 4 — ML
  |
  v
Backend
  |
  v
Frontend
```

Role 1 does **not** contain Role 2, Role 4, backend, or frontend source.

## Safety / lab boundary

This package is intended for an isolated cyber range or authorized testbed. Generated scenarios are capped by default and target `127.0.0.0/8` or RFC1918 addresses only. The built-in "slow HTTP" and tunnel scenarios generate representative packet/metadata patterns for dataset creation rather than contacting public systems or providing an unrestricted attack launcher.

For real traffic appliances such as TRex/Ostinato/iperf3, the package only supplies bounded adapter commands/configuration; run them strictly against your own lab endpoints.

## Requirements

- Python 3.10+
- Linux recommended for namespace/data-diode validation scripts
- Scapy for PCAP generation
- Optional: iperf3, TRex, Ostinato, Wireshark/tshark

Install:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell activation:

```powershell
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

## Quick start

Generate the complete demo dataset:

```bash
python -m app.cli dataset --config configs/demo.yaml
```

Outputs:

```text
data/pcap/role1_demo.pcap
 data/labels/role1_demo.jsonl
 data/labels/role1_demo_manifest.json
```

Run tests:

```bash
pytest -q
```

## Scenarios

### Benign baseline

Produces mixed TCP/UDP flows with configurable packet size, rate, duration, source/destination diversity, and reproducible randomness.

### SYN / UDP flood patterns

Produces capped, synthetic flood-like packet patterns in a lab PCAP. Default limits keep datasets small and deterministic. Increase caps only on an isolated benchmark network.

### Slow HTTP pattern simulation

Creates a labeled sequence with many small application-like request fragments and long inter-arrival gaps. It is designed for training/benchmarking Role 2/Role 4 features without automatically opening long-lived connections to another host.

### DNS tunneling-like dataset

Creates DNS queries containing generated base32-like labels and tracks entropy, length and query-rate labels. It does not create a live tunneling channel.

### C2 beaconing

Creates periodic TCP flows with stable inter-arrival times plus mild jitter. These are ideal for Role 2 IAT/periodicity features and Role 4 C2 sequence detection.

## Role 2 handoff

Each generated record is tagged with:

- `scenario`
- `label`
- `flow_id`
- `timestamp`
- `source_ip`
- `destination_ip`
- `protocol`
- `source_port`
- `destination_port`

The generated PCAPs can be passed directly to the separate Role 2 package.

## High-throughput external engines

The package contains bounded adapter templates:

- `configs/iperf3_baseline.yaml`
- `configs/trex_baseline.yaml`
- `configs/ostinato_baseline.yaml`

These are configuration/command templates, not unrestricted attack automation.

## One-way / data-diode lab validation

For a real hardware diode testbed:

1. Put the traffic generator on the source side.
2. Mirror/copy traffic into the monitoring side through the diode.
3. Keep the monitoring side on a dedicated capture interface.
4. Run `scripts/check_one_way.sh` on the monitoring enclave.
5. Verify packets are observed in the forward direction and that no route/interface exists for a reverse path.
6. For hardware validation, physically confirm the diode LED/status and vendor diagnostics.

The script checks local route/interface state and capture direction; it cannot certify the physical hardware internals of a vendor diode.

## Suggested lab topology

```text
[Generator VM / Linux]
        |
        |  forward-only mirror
        v
[Hardware Data Diode]
        |
        v
[Monitoring Capture NIC]
        |
        v
[Role 2]
        |
        v
[Role 4 ML]
```

## External tool usage

### iperf3

Use only between your own lab endpoints. Example baseline configuration is provided in `configs/iperf3_baseline.yaml`.

### TRex

Use the supplied profile only on a private benchmark network. Keep rate and packet counts within your testbed capacity.

### Ostinato

Import the supplied traffic profile and keep the destination within the lab RFC1918 range.

### Wireshark / tshark

Use to inspect generated PCAPs and confirm that the expected labels/patterns are present.

## Dataset lifecycle

```text
Role 1 generator
   -> PCAP + JSONL labels
   -> Role 2 parser/features
   -> Role 4 training/evaluation
   -> Backend/Frontend demonstration
```

## Files

- `app/cli.py` — command line entry point
- `app/scenarios.py` — scenario generators
- `app/dataset.py` — PCAP + label writer
- `app/safety.py` — private-target guardrails
- `configs/demo.yaml` — reproducible default dataset
- `scripts/check_one_way.sh` — Linux directionality checks
- `tests/` — unit tests
