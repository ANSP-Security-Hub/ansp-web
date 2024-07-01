from typing import Optional
from pydantic import BaseModel


class Site(BaseModel):
    name: str
    duration: int
    total_bytes: int
    total_packets: int
    visits: int
    # optional fields
    country: Optional[str] = None
    asn: Optional[str] = None
    city: Optional[str] = None

