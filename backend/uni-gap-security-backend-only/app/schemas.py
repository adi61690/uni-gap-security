from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict

ThreatClass = Literal["DDoS", "Botnet C2", "DGA / DNS Tunneling", "Encrypted Malware", "Recon / Port Scan", "Data Exfiltration"]
Severity = Literal["Critical", "High", "Medium", "Low"]

class LoginRequest(BaseModel):
    username: str
    password: str
    remember: bool = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict
    session_id: str

class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Literal["dns", "encrypted_session", "flow"]
    timestamp: str | None = None
    flow_id: str | None = None
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    destination_port: int = 0
    protocol: str = "UNKNOWN"
    domain: str | None = None
    dns_record_type: str = "A"
    dns_query_rate: float = 0.0
    packet_sizes: list[float] = Field(default_factory=list)
    timestamps: list[float] = Field(default_factory=list)
    ja3: str = ""
    ja4: str = ""
    tls_version: str = ""
    quic: bool = False

class AlertFilter(BaseModel):
    q: str | None = None
    threat_class: str | None = None
    severity: str | None = None
    min_confidence: float | None = None
    limit: int = Field(default=100, le=500)

class IncidentUpdate(BaseModel):
    status: str | None = None
    note: str | None = None

class SettingUpdate(BaseModel):
    values: dict[str, Any]

class HuntRequest(BaseModel):
    q: str = ""
    threat_class: str | None = None
    protocol: str | None = None
    min_confidence: float = 0

class ReportRequest(BaseModel):
    name: str = "Uni-Gap Threat Report"
    export: bool = True

class ConnectionTestRequest(BaseModel):
    endpoint: str | None = None
    kind: str = "websocket"
