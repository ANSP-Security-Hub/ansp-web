from fastapi import APIRouter, HTTPException

from schemas.device import DeviceDetails
from services.devices import DeviceService

router = APIRouter()


@router.get("/device_details/{device_id}", response_model=DeviceDetails)
async def get_device_details(device_id: str) -> DeviceDetails:
    device_details = DeviceService.get_device_details(device_id)
    if not device_details:
        raise HTTPException(status_code=404, detail="Device not found")

    return device_details
