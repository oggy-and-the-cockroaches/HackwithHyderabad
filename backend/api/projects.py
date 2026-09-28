"""API endpoints for project management."""

import os
import uuid
import shutil
import aiofiles
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional

from models.schemas import ProjectCreate, ProjectResponse, ScanCreate, ScanResponse
from database.schema import get_db, get_project_dir
from services.scanner import ScannerService
from services.hindsight import HindsightService

router = APIRouter(prefix="/api/projects", tags=["projects"])

# In-memory scan tracking (in production, use Redis or database)
scan_status = {}


@router.post("", response_model=ProjectResponse)
async def create_project(project: ProjectCreate):
    """Create a new project (without upload)."""
    project_id = str(uuid.uuid4())
    project_dir = get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO projects (id, name, project_context)
            VALUES (?, ?, ?)
        """, (project_id, project.name, project.project_context))

    return ProjectResponse(
        id=project_id,
        name=project.name,
        created_at=datetime.utcnow(),
        project_context=project.project_context
    )


@router.post("/{project_id}/upload")
async def upload_project(
    project_id: str,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """Upload a project ZIP file."""
    project_dir = get_project_dir(project_id)

    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    # Clear existing project files
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)

    # Save and extract ZIP
    zip_path = project_dir / "project.zip"
    async with aiofiles.open(zip_path, 'wb') as f:
        content = await file.read()
        await f.write(content)

    # Extract ZIP
    import zipfile
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(project_dir)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")

    # Remove ZIP after extraction
    zip_path.unlink()

    # Detect project structure
    from services.project_detector import detect_project
    project_context = detect_project(str(project_dir))

    # Update project context in database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE projects SET project_context = ? WHERE id = ?
        """, (json.dumps(project_context), project_id))

    return {
        "project_id": project_id,
        "message": "Project uploaded and extracted successfully",
        "detected_technologies": project_context
    }


@router.get("", response_model=List[ProjectResponse])
async def list_projects():
    """List all projects."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, created_at, last_scan_at, project_context FROM projects ORDER BY created_at DESC")
        projects = []
        for row in cursor.fetchall():
            import json
            projects.append(ProjectResponse(
                id=row[0],
                name=row[1],
                created_at=row[2],
                last_scan_at=row[3],
                project_context=json.loads(row[4]) if row[4] else None
            ))
        return projects


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str):
    """Get project details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, created_at, last_scan_at, project_context FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")

        import json
        return ProjectResponse(
            id=row[0],
            name=row[1],
            created_at=row[2],
            last_scan_at=row[3],
            project_context=json.loads(row[4]) if row[4] else None
        )


@router.delete("/{project_id}")
async def delete_project(project_id: str):
    """Delete a project and all its data."""
    project_dir = get_project_dir(project_id)

    # Delete from database (cascades to scans, findings)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Project not found")

    # Delete project files
    if project_dir.exists():
        shutil.rmtree(project_dir)

    return {"message": "Project deleted successfully"}


# Import datetime at the top
from datetime import datetime
import json