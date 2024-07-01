from fastapi import APIRouter, HTTPException

from schemas.speed import Speed
from schemas.website import Site
from schemas.device import Device
from services.speed import SpeedService
from services.top_sites import SiteService
from services.devices import DeviceService

router = APIRouter(prefix="/main")


@router.get("/top_sites/{num}", response_model=list[Site])
async def get_top_sites(num: int) -> list[Site]:
    top_sites = SiteService.get_top_sites(num)
    if not top_sites:
        raise HTTPException(status_code=404, detail="No sites found")

    return top_sites


@router.get("/devices", response_model=list[Device])
async def get_devices() -> list[Device]:
    devices = DeviceService.get_devices()
    if not devices:
        raise HTTPException(status_code=404, detail="No devices found")

    return devices


@router.get("/speed", response_model=Speed)
async def get_speed() -> Speed:
    speed = SpeedService.get_speed()
    if not speed:
        raise HTTPException(status_code=404, detail="Speed data not available")

    return speed
