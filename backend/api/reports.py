"""API endpoints for scan reports and findings."""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime

from models.schemas import FindingResponse, ScanComparison
from database.schema import get_db
from services.hindsight import HindsightService

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/scan/{scan_id}")
async def get_scan_report(scan_id: str):
    """Get full scan report with all findings."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get scan info
        cursor.execute("""
            SELECT id, project_id, status, created_at, completed_at, summary
            FROM scans WHERE id = ?
        """, (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings
        cursor.execute("""
            SELECT id, scan_id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan
            FROM findings WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END
        """, (scan_id,))

        findings = []
        for row in cursor.fetchall():
            findings.append(FindingResponse(
                id=row[0], scan_id=row[1], category=row[2], severity=row[3],
                title=row[4], description=row[5], evidence=row[6],
                file_path=row[7], line_number=row[8], confidence=row[9],
                recommendation=row[10], status=row[11],
                first_detected_scan=row[12], last_detected_scan=row[13]
            ))

        import json
        return {
            "scan": {
                "id": scan[0], "project_id": scan[1], "status": scan[2],
                "created_at": scan[3], "completed_at": scan[4],
                "summary": json.loads(scan[5]) if scan[5] else {}
            },
            "findings": findings,
            "total_findings": len(findings)
        }


@router.get("/scan/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """Get findings for a scan with optional filters."""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT id, scan_id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan
            FROM findings WHERE scan_id = ?
        """
        params = [scan_id]

        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += """
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END
        """

        cursor.execute(query, params)

        findings = []
        for row in cursor.fetchall():
            findings.append(FindingResponse(
                id=row[0], scan_id=row[1], category=row[2], severity=row[3],
                title=row[4], description=row[5], evidence=row[6],
                file_path=row[7], line_number=row[8], confidence=row[9],
                recommendation=row[10], status=row[11],
                first_detected_scan=row[12], last_detected_scan=row[13]
            ))

        return findings


@router.get("/scan/{scan_id}/comparison", response_model=ScanComparison)
async def get_scan_comparison(scan_id: str):
    """Get comparison with previous scan."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get project_id for this scan
        cursor.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        project_id = scan[0]

        # Use Hindsight to compare
        hindsight = HindsightService()

        # Get current findings
        cursor.execute("""
            SELECT id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan
            FROM findings WHERE scan_id = ?
        """, (scan_id,))

        from scanners.base import Finding
        current_findings = []
        for row in cursor.fetchall():
            f = Finding(
                category=row[1], severity=row[2], title=row[3], description=row[4],
                evidence=row[5], file_path=row[6], line_number=row[7],
                confidence=row[8], recommendation=row[9], status=row[10]
            )
            f.metadata["first_detected_scan"] = row[11]
            f.metadata["last_detected_scan"] = row[12]
            f.id = row[0]
            current_findings.append(f)

        comparison = hindsight.compare_scans(project_id, scan_id, current_findings)
        hindsight.close()

        return ScanComparison(
            current_scan_id=scan_id,
            previous_scan_id=comparison.get("previous_scan_id"),
            previous_findings_count=comparison.get("previous_findings_count", 0),
            current_findings_count=len(current_findings),
            fixed_count=comparison.get("fixed_count", 0),
            unresolved_count=comparison.get("unresolved_count", 0),
            new_count=comparison.get("new_count", 0),
            reintroduced_count=comparison.get("reintroduced_count", 0),
            fixed_findings=comparison.get("fixed_findings", []),
            unresolved_findings=comparison.get("unresolved_findings", []),
            new_findings=comparison.get("new_findings", []),
            reintroduced_findings=comparison.get("reintroduced_findings", [])
        )


@router.get("/project/{project_id}/history")
async def get_project_history(project_id: str):
    """Get scan history for a project."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
        """, (project_id,))

        import json
        history = []
        for row in cursor.fetchall():
            history.append({
                "scan_id": row[0],
                "status": row[1],
                "created_at": row[2],
                "completed_at": row[3],
                "summary": json.loads(row[4]) if row[4] else {}
            })

        return {"project_id": project_id, "history": history}


@router.post("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, status: str):
    """Update finding status (open, fixed, acknowledged)."""
    valid_statuses = ["open", "fixed", "acknowledged"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found")

    return {"message": "Finding status updated", "finding_id": finding_id, "status": status}


@router.post("/projects/{project_id}/notes")
async def add_developer_note(project_id: str, finding_id: Optional[str], type: str, content: str):
    """Add a developer note/decision to Hindsight."""
    valid_types = ["note", "exception", "decision"]
    if type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid type. Must be one of: {valid_types}")

    hindsight = HindsightService()
    hindsight.add_developer_note(project_id, finding_id, type, content)
    hindsight.close()

    return {"message": "Note added successfully"}


@router.get("/projects/{project_id}/notes")
async def get_developer_notes(project_id: str, finding_id: Optional[str] = None):
    """Get developer notes for a project or finding."""
    hindsight = HindsightService()
    notes = hindsight.get_developer_notes(project_id, finding_id)
    hindsight.close()

    return {"notes": notes}