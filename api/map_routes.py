from fastapi import APIRouter, HTTPException

from schemas.map import CountryConnections
from services.map import MapService

router = APIRouter()


@router.get("/map", response_model=list[CountryConnections])
async def world_map() -> list[CountryConnections] | None:
    res = MapService.get_all_country_connections()
    if not res:
        raise HTTPException(status_code=404, detail="No data found")

    return res



@router.get("/map/{id}", response_model=list[CountryConnections])
async def world_map_by_device(id: str) -> list[CountryConnections] | None:
    res = MapService.get_country_connections_by_device(id)
    if not res:
        raise HTTPException(status_code=404, detail="No data found")

    return res
