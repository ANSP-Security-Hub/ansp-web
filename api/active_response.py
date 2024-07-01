from fastapi import APIRouter, HTTPException

from services.active_response import ActiveResponseService

router = APIRouter()


@router.post("/active_response/pihole/block-domain")
async def block_domain(domain: str):
    res = ActiveResponseService.block_domain(domain)
    if not res:
        raise HTTPException(status_code=404, detail="Failed to block domain")

    return {"message": f"Domain {domain} blocked"}


@router.post("/active_response/pihole/allow-domain")
async def allow_domain(domain: str):
    res = ActiveResponseService.allow_domain(domain)
    if not res:
        raise HTTPException(status_code=404, detail="Failed to allow domain")

    return {"message": f"Domain {domain} allowed"}

