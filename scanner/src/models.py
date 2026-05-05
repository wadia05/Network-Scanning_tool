from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
from enum import Enum


class OSFamily(str, Enum):
    WINDOWS        = "Windows"
    LINUX          = "Linux"
    MACOS          = "macOS"
    IOS            = "iOS"
    ANDROID        = "Android"
    NETWORK_DEVICE = "Network Device"   # routeur, switch, AP
    IOT            = "IoT"              # caméra, imprimante, etc.
    UNKNOWN        = "Unknown"


class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


# ── Résultat du fingerprinting ────────────────────────────────

class FingerprintResult(BaseModel):

    # Famille d'OS détectée
    os_family      : OSFamily = OSFamily.UNKNOWN

    # Version précise si détectable
    # ex: "Windows 11", "iOS 16.2", "Ubuntu 22.04"
    os_version     : Optional[str] = None

    # Fabricant de l'appareil (téléphone, laptop...)
    # ex: "Apple", "Samsung", "Dell"
    device_vendor  : Optional[str] = None

    # Type d'appareil
    # ex: "Smartphone", "Laptop", "Router", "Smart TV"
    device_type    : Optional[str] = None

    # Niveau de confiance global (0.0 → 1.0)
    confidence     : float = 0.0

    # Détail par technique utilisée
    # ex: {"mac": "Apple Inc.", "tcp": "iOS/macOS", "dhcp": "iPhone"}
    sources        : dict = Field(default_factory=dict)

    # Données brutes TCP collectées (pour debug / rapport PFE)
    tcp_ttl        : Optional[int]  = None
    tcp_window     : Optional[int]  = None
    tcp_options    : Optional[list] = None
    icmp_response  : Optional[bool] = None

    def summary(self) -> str:
        """Résumé lisible pour le dashboard."""
        base = self.os_version or self.os_family.value
        if self.device_vendor:
            return f"{self.device_vendor} — {base}"
        return base


# ── Port ──────────────────────────────────────────────────────

class Port(BaseModel):
    number  : int
    state   : PortState
    service : str = "unknown"
    banner  : Optional[str] = None   # ex: "Apache/2.4 (Win64)"

    @field_validator("number")
    @classmethod
    def port_range(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError(f"Port invalide : {v}")
        return v


# ── Device ────────────────────────────────────────────────────

class Device(BaseModel):
    ip          : str
    mac         : str
    hostname    : str                     = "unknown"

    # Fabricant depuis OUI (couche MAC)
    mac_vendor  : str                     = "Unknown"

    # Résultat complet du fingerprinting
    fingerprint : Optional[FingerprintResult] = None

    ports       : list[Port]              = Field(default_factory=list)
    is_online   : bool                    = True
    first_seen  : datetime                = Field(default_factory=datetime.now)
    last_seen   : datetime                = Field(default_factory=datetime.now)

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, v):
        clean = v.replace("-", ":").upper()
        if len(clean.replace(":", "")) != 12:
            raise ValueError(f"MAC invalide : {v}")
        return clean

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v):
        import re
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            raise ValueError(f"IP invalide : {v}")
        return v

    def get_open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    def display_name(self) -> str:
        """Nom affiché sur le dashboard."""
        if self.fingerprint and self.fingerprint.device_vendor:
            return f"{self.fingerprint.device_vendor} ({self.ip})"
        if self.hostname != "unknown":
            return f"{self.hostname} ({self.ip})"
        return self.ip

    def to_json(self) -> dict:
        return self.model_dump(mode="json")

    def mark_offline(self):
        self.is_online = False
        self.last_seen = datetime.now()


# ── ScanResult ────────────────────────────────────────────────

class ScanResult(BaseModel):
    network     : str
    timestamp   : datetime     = Field(default_factory=datetime.now)
    devices     : list[Device] = Field(default_factory=list)
    total_hosts : int          = 0
    scan_id     : Optional[int] = None

    def model_post_init(self, __context):
        self.total_hosts = len(self.devices)

    def get_new_devices(self, previous: "ScanResult") -> list[Device]:
        previous_macs = {d.mac for d in previous.devices}
        return [d for d in self.devices if d.mac not in previous_macs]

    def get_lost_devices(self, previous: "ScanResult") -> list[Device]:
        current_macs = {d.mac for d in self.devices}
        return [d for d in previous.devices if d.mac not in current_macs]

    def to_json(self) -> dict:
        return self.model_dump(mode="json")