from typing import Optional

from pydantic import BaseModel

from schemas.website import Site
from schemas.device import Health


class CountryConnections(BaseModel):
    country: str
    total_count: int
    count_by_status: Optional[dict[Health, int]] = None
    sites: Optional[list[Site]] = None
