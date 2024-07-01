from typing import Optional

from pydantic import BaseModel


class Speed(BaseModel):
    download_speed: float
    upload_speed: Optional[float] = None
