from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict

class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")
    dns_entropy: Optional[float] = None
    dns_query_length: Optional[int] = None
    dns_record_type: Optional[str] = None
    dns_ngram_score: Optional[float] = None
    dns_query_rate: Optional[float] = None
    anomaly_score: Optional[float] = None
    packet_rate: Optional[float] = None
    flow_rate: Optional[float] = None
    amplification_factor: Optional[float] = None
    beacon_interval: Optional[float] = None
    iat_cv: Optional[float] = None
    destination_count: Optional[int] = None
    periodicity_score: Optional[float] = None
    dominant_frequency_hz: Optional[float] = None
    fft_magnitude: Optional[float] = None
    autocorrelation_peak: Optional[float] = None
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    tls_metadata: Optional[Dict[str, Any]] = None
    quic_metadata: Optional[Dict[str, Any]] = None
    packet_size_statistics: Optional[Dict[str, float]] = None
    timing_statistics: Optional[Dict[str, float]] = None
    normal_range: Dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[str] = None
    feature_values: Dict[str, Any] = Field(default_factory=dict)

class ModelInfo(BaseModel):
    name: str
    version: str
    latency_ms: float
    class_scores: Dict[str, float] = Field(default_factory=dict)
    model_type: str = "CatBoost"
    sequence_model_used: bool = False

class Alert(BaseModel):
    timestamp: str
    flow_id: str
    threat_class: Literal["DDoS", "Botnet C2", "DGA / DNS Tunneling", "Encrypted Malware", "Recon / Port Scan", "Data Exfiltration"]
    threat_subtype: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    confidence: float = Field(ge=0, le=1)
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    evidence: Evidence
    model: ModelInfo
    evidence_summary: str
    security_context: Dict[str, Any] = Field(default_factory=lambda: {
        "read_only_observation": True,
        "one_way_ingest": True,
        "no_active_probing": True,
        "no_return_path": True,
        "no_inline_mitigation": True,
        "payload_decrypted": False,
        "metadata_only": True,
    })

class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Literal["dns", "encrypted_session"]
    timestamp: Optional[str] = None
    flow_id: Optional[str] = None
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    destination_port: int = 0
    protocol: str = "UNKNOWN"
    domain: Optional[str] = None
    dns_record_type: str = "A"
    dns_query_rate: float = 0.0
    packet_sizes: List[float] = Field(default_factory=list)
    timestamps: List[float] = Field(default_factory=list)
    ja3: str = ""
    ja4: str = ""
    tls_version: str = ""
    quic: bool = False

class PredictResponse(BaseModel):
    is_alert: bool
    alert: Optional[Alert] = None
    observation: Dict[str, Any] = Field(default_factory=dict)
