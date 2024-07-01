from enum import Enum
from typing import Optional

from pydantic import BaseModel

from schemas.website import Site


class Health(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    def __str__(self):
        return self.value


class Status(Enum):
    ACTIVE = "active"
    DISCONNECTED = "disconnected"

    def __str__(self):
        return self.value


class Device(BaseModel):
    id: str
    name: Optional[str] = None
    ip: str
    health: Health
    status: Status
    uptime: Optional[int] = None
    last_connected: Optional[int] = None


class DeviceDetails(Device):
    os: str
    used_bandwidth: int
    top_sites: Optional[list[Site]] = None
    alert_count: Optional[dict[str, int]] = None  # { "low": 0, "medium": 0, "high": 0 }
    alerts: Optional[dict[str, list]] = None  # { "medium": [], "high": [] }


