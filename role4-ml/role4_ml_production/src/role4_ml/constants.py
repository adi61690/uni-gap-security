from enum import Enum

class ThreatClass(str, Enum):
    DGA_DNS = "DGA / DNS Tunneling"
    ENCRYPTED_MALWARE = "Encrypted Malware"
    BOTNET_C2 = "Botnet C2"

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

MODEL_VERSION = "role4-2.0.0-demo"
