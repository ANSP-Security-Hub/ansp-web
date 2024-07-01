#!./venv/bin/python3

from fastapi import FastAPI
from api.health_routes import router as health_router
from api.main_routes import router as main_router
from api.device_details import router as device_details_router
from api.map_routes import router as map_router
from api.active_response import router as active_response_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Include API routers
app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(main_router, prefix="/api/v1", tags=["Main"])
app.include_router(device_details_router, prefix="/api/v1", tags=["Device Details"])
app.include_router(map_router, prefix="/api/v1", tags=["Country Connections Map"])
app.include_router(active_response_router, prefix="/api/v1", tags=["Active Response"])

# CORS (Cross-Origin Resource Sharing) middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    # Run the FastAPI application using Uvicorn with auto-reload
    uvicorn.run(app, host="0.0.0.0", port=8000)