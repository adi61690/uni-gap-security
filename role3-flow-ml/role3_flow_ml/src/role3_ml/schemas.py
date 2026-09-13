from __future__ import annotations
from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict

ThreatClass = Literal['DDoS','Botnet C2','Recon / Port Scan','Data Exfiltration']
Severity = Literal['Critical','High','Medium','Low']

class FlowFeatures(BaseModel):
    model_config = ConfigDict(extra='allow')
    schema_version: str = 'role2.v2'
    flow_id: str
    timestamp_start: str
    timestamp_end: str
    duration_seconds: float = 0
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = 'OTHER'
    packets: int = 0
    bytes_total: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0
    byte_packet_ratio: float = 0
    directional_symmetry: float = 0
    source_ip_entropy: float = 0
    destination_ip_entropy: float = 0
    unique_source_ips: int = 1
    unique_destination_ips: int = 1
    packet_rate: float = 0
    byte_rate: float = 0
    packet_sizes: list[int] = Field(default_factory=list)
    inter_arrival_times: list[float] = Field(default_factory=list)
    burstiness: float = 0
    tls_metadata: dict[str, Any] = Field(default_factory=dict)
    quic_metadata: dict[str, Any] = Field(default_factory=dict)
    ingest_source: str = 'pcap'
    passive_guardrails: dict[str, bool] = Field(default_factory=lambda: {
        'read_only': True, 'active_probing': False, 'return_path': False,
        'payload_decryption': False, 'payload_persistence': False,
    })

class Evidence(BaseModel):
    model_config = ConfigDict(extra='allow')
    anomaly_score: float | None = None
    packet_rate: float | None = None
    flow_rate: float | None = None
    source_ip_entropy: float | None = None
    destination_ip_entropy: float | None = None
    amplification_factor: float | None = None
    fanout: int | None = None
    unique_destination_hosts: int | None = None
    unique_destination_ports: int | None = None
    scan_rate: float | None = None
    beacon_interval: float | None = None
    iat_cv: float | None = None
    periodicity_score: float | None = None
    dominant_frequency_hz: float | None = None
    fft_magnitude: float | None = None
    autocorrelation_peak: float | None = None
    outbound_bytes: float | None = None
    inbound_bytes: float | None = None
    outbound_inbound_ratio: float | None = None
    flow_duration: float | None = None
    volume_asymmetry: float | None = None
    packet_size_statistics: dict[str, float] = Field(default_factory=dict)
    timing_statistics: dict[str, float] = Field(default_factory=dict)
    normal_range: dict[str, Any] = Field(default_factory=dict)
    explanation: str = ''
    feature_values: dict[str, Any] = Field(default_factory=dict)

class ModelInfo(BaseModel):
    name: str
    version: str
    latency_ms: float
    class_scores: Dict[str, float] = Field(default_factory=dict)
    model_type: str = 'Ensemble'
    sequence_model_used: bool = False

class Alert(BaseModel):
    timestamp: str
    flow_id: str
    threat_class: ThreatClass
    threat_subtype: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    source_ip: str
    destination_ip: str
    destination_port: int = 0
    protocol: str
    evidence: Evidence
    model: ModelInfo
    evidence_summary: str
    security_context: Dict[str, Any] = Field(default_factory=lambda: {
        'read_only_observation': True,'one_way_ingest': True,'no_active_probing': True,
        'no_return_path': True,'no_inline_mitigation': True,'payload_decrypted': False,
        'metadata_only': True,
    })

class PredictResponse(BaseModel):
    is_alert: bool
    alert: Optional[Alert] = None
    observation: Dict[str, Any] = Field(default_factory=dict)
