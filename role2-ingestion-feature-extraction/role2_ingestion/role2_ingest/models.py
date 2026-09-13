from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict

Protocol = Literal['TCP','UDP','ICMP','DNS','TLS','QUIC','OTHER']
InputType = Literal['pcap','pcapng','netflow','ipfix','sflow','zeek','json']
Direction = Literal['forward','reverse','unknown']

class PacketMetadata(BaseModel):
    model_config = ConfigDict(extra='ignore')
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = 'OTHER'
    packet_length: int = 0
    direction: Direction = 'unknown'
    tcp_flags: str | None = None
    # Intentionally NOT stored or emitted: application payload bytes.
    tls: dict[str, Any] = Field(default_factory=dict)
    quic: dict[str, Any] = Field(default_factory=dict)
    input_source: InputType = 'pcap'

class FlowFeatures(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: str = 'role2.v2'
    flow_id: str
    timestamp_start: str
    timestamp_end: str
    duration_seconds: float
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    packets: int
    bytes_total: int
    forward_packets: int
    reverse_packets: int
    forward_bytes: int
    reverse_bytes: int
    byte_packet_ratio: float
    directional_symmetry: float
    source_ip_entropy: float
    destination_ip_entropy: float
    unique_source_ips: int
    unique_destination_ips: int
    packet_rate: float
    byte_rate: float
    packet_sizes: list[int]
    inter_arrival_times: list[float]
    burstiness: float
    tls_metadata: dict[str, Any] = Field(default_factory=dict)
    quic_metadata: dict[str, Any] = Field(default_factory=dict)
    ingest_source: InputType
    passive_guardrails: dict[str, bool] = Field(default_factory=lambda: {
        'read_only': True,
        'active_probing': False,
        'return_path': False,
        'payload_decryption': False,
        'payload_persistence': False,
    })

class IngestEvent(BaseModel):
    source: InputType
    data: dict[str, Any] | list[dict[str, Any]]
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class HandoffEnvelope(BaseModel):
    schema_version: str = 'role2.v2'
    producer: str = 'uni-gap-role2'
    produced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    feature: FlowFeatures
