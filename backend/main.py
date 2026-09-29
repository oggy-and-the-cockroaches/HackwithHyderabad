"""Main FastAPI application for Shipcheck AI Pre-Ship Auditor."""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from database.schema import init_db
from api import projects, scans, reports, hindsight
from services.hindsight import HindsightService


# Initialize database synchronously before app creation
init_db()
print("Database initialized")

# Create projects directory
projects_dir = os.environ.get("SHIPCHECK_PROJECTS_DIR", "./projects")
os.makedirs(projects_dir, exist_ok=True)


app = FastAPI(
    title="Shipcheck - AI Pre-Ship Auditor",
    description="AI-powered software pre-ship auditor with Hindsight memory",
    version="1.0.0",
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(hindsight.router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "shipcheck"}


@app.get("/api/version")
async def version():
    """Version endpoint."""
    return {"version": "1.0.0", "name": "Shipcheck"}


import sys

# Serve frontend static files
if getattr(sys, "frozen", False):
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
    frontend_dir = os.path.join(base_dir, "frontend")
else:
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_frontend():
        """Serve the frontend index.html."""
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend not found."}

    @app.get("/{path:path}")
    async def serve_frontend_paths(path: str):
        """Serve frontend for client-side routing."""
        # Don't intercept API routes
        if path.startswith("api/") or path == "health" or path.startswith("projects/") or path.startswith("scans/") or path.startswith("reports/"):
            raise HTTPException(status_code=404, detail="Not found")

        file_path = os.path.join(frontend_dir, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)

        # Fallback to index.html for SPA routing
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)

        return {"message": "Not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)