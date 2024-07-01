# api/health_routes.py

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint to verify the status of the application.
    """
    return {"status": "ok"}
