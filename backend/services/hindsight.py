"""Hindsight memory service for tracking scan history and comparisons."""

import json
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from database.schema import get_db, get_connection
from scanners.base import Finding


class HindsightService:
    """Manages persistent memory across scans for a project."""

    def __init__(self):
        self.conn = get_connection()

    def close(self):
        if self.conn:
            self.conn.close()

    def save_scan_results(self, project_id: str, scan_id: str, project_context: Dict[str, Any], findings: List[Finding]):
        """Save scan results to Hindsight memory."""
        cursor = self.conn.cursor()

        # Update project context
        cursor.execute("""
            INSERT OR REPLACE INTO projects (id, name, project_context, last_scan_at)
            VALUES (?, ?, ?, ?)
        """, (project_id, project_context.get("name", "Unknown Project"), json.dumps(project_context), datetime.utcnow().isoformat()))

        # Update scan record
        summary = {
            "total_findings": len(findings),
            "by_category": self._count_by_category(findings),
            "by_severity": self._count_by_severity(findings)
        }
        cursor.execute("""
            INSERT OR REPLACE INTO scans (id, project_id, status, completed_at, summary)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, project_id, "completed", datetime.utcnow().isoformat(), json.dumps(summary)))

        # Save findings with hindsight tracking
        for finding in findings:
            finding_id = self._get_or_create_finding_id(project_id, finding)
            cursor.execute("""
                INSERT OR REPLACE INTO findings (id, scan_id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, scan_id, finding.category, finding.severity, finding.title,
                finding.description, finding.evidence, finding.file_path, finding.line_number,
                finding.confidence, finding.recommendation, finding.status,
                finding.metadata.get("first_detected_scan", scan_id),
                scan_id
            ))

        self.conn.commit()

    def _get_or_create_finding_id(self, project_id: str, finding: Finding) -> str:
        """Get existing finding ID or create new one based on similarity."""
        cursor = self.conn.cursor()

        # Try to find similar existing finding (same category, title, file_path, line_number)
        cursor.execute("""
            SELECT id, first_detected_scan FROM findings
            WHERE category = ? AND title = ? AND file_path = ? AND line_number = ?
            ORDER BY last_detected_scan DESC LIMIT 1
        """, (finding.category, finding.title, finding.file_path, finding.line_number))

        row = cursor.fetchone()
        if row:
            finding_id, first_scan = row
            # Update metadata
            finding.metadata["first_detected_scan"] = first_scan
            return finding_id

        # Create new finding ID
        return str(uuid.uuid4())

    def _count_by_category(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def compare_scans(self, project_id: str, current_scan_id: str, current_findings: List[Finding]) -> Dict[str, Any]:
        """Compare current scan with previous scan."""
        cursor = self.conn.cursor()

        # Get previous scan
        cursor.execute("""
            SELECT id FROM scans
            WHERE project_id = ? AND id != ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        """, (project_id, current_scan_id))

        prev_scan = cursor.fetchone()
        if not prev_scan:
            return {
                "has_previous_scan": False,
                "previous_scan_id": None,
                "fixed_count": 0,
                "unresolved_count": 0,
                "new_count": len(current_findings),
                "reintroduced_count": 0,
                "fixed_findings": [],
                "unresolved_findings": [],
                "new_findings": [f.to_dict() for f in current_findings],
                "reintroduced_findings": []
            }

        prev_scan_id = prev_scan[0]

        # Get previous findings
        cursor.execute("""
            SELECT id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan
            FROM findings WHERE scan_id = ?
        """, (prev_scan_id,))

        prev_findings = {}
        for row in cursor.fetchall():
            key = self._finding_key(row[1], row[3], row[5], row[6])  # category, title, evidence, file_path
            prev_findings[key] = {
                "id": row[0], "category": row[1], "severity": row[2], "title": row[3],
                "description": row[4], "evidence": row[5], "file_path": row[6],
                "line_number": row[7], "confidence": row[8], "recommendation": row[9],
                "status": row[10], "first_detected_scan": row[11], "last_detected_scan": row[12]
            }

        # Compare
        current_keys = set()
        fixed = []
        unresolved = []
        new_findings = []
        reintroduced = []

        for finding in current_findings:
            key = self._finding_key(finding.category, finding.title, finding.evidence, finding.file_path)
            current_keys.add(key)

            if key in prev_findings:
                prev = prev_findings[key]
                if prev["status"] == "fixed":
                    # Was fixed, now reappeared
                    reintroduced.append(prev)
                else:
                    # Still unresolved
                    unresolved.append(prev)
            else:
                # New finding
                new_findings.append(finding.to_dict())

        # Check for fixed findings (in previous but not in current)
        for key, prev in prev_findings.items():
            if key not in current_keys and prev["status"] != "fixed":
                fixed.append(prev)

        return {
            "has_previous_scan": True,
            "previous_scan_id": prev_scan_id,
            "fixed_count": len(fixed),
            "unresolved_count": len(unresolved),
            "new_count": len(new_findings),
            "reintroduced_count": len(reintroduced),
            "fixed_findings": fixed,
            "unresolved_findings": unresolved,
            "new_findings": new_findings,
            "reintroduced_findings": reintroduced
        }

    def _finding_key(self, category: str, title: str, evidence: str, file_path: Optional[str]) -> str:
        """Create a unique key for a finding."""
        return f"{category}:{title}:{file_path}:{evidence[:50] if evidence else ''}"

    def get_project_context(self, project_id: str) -> Dict[str, Any]:
        """Get project context including previous scan summary."""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id, name, project_context, created_at, last_scan_at
            FROM projects WHERE id = ?
        """, (project_id,))

        project = cursor.fetchone()
        if not project:
            return {}

        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 5
        """, (project_id,))

        scans = []
        for row in cursor.fetchall():
            scans.append({
                "id": row[0], "status": row[1], "created_at": row[2],
                "completed_at": row[3], "summary": json.loads(row[4]) if row[4] else {}
            })

        return {
            "project": {
                "id": project[0], "name": project[1],
                "project_context": json.loads(project[2]) if project[2] else {},
                "created_at": project[3], "last_scan_at": project[4]
            },
            "recent_scans": scans
        }

    def add_developer_note(self, project_id: str, finding_id: Optional[str], note_type: str, content: str):
        """Add a developer note/decision to Hindsight."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO hindsight_memory (project_id, finding_id, type, content)
            VALUES (?, ?, ?, ?)
        """, (project_id, finding_id, note_type, content))
        self.conn.commit()

    def get_developer_notes(self, project_id: str, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get developer notes for a project or specific finding."""
        cursor = self.conn.cursor()
        if finding_id:
            cursor.execute("""
                SELECT id, finding_id, type, content, created_at
                FROM hindsight_memory WHERE project_id = ? AND finding_id = ?
                ORDER BY created_at DESC
            """, (project_id, finding_id))
        else:
            cursor.execute("""
                SELECT id, finding_id, type, content, created_at
                FROM hindsight_memory WHERE project_id = ?
                ORDER BY created_at DESC
            """, (project_id,))

        notes = []
        for row in cursor.fetchall():
            notes.append({
                "id": row[0], "finding_id": row[1], "type": row[2],
                "content": row[3], "created_at": row[4]
            })
        return notes

    def update_finding_status(self, finding_id: str, status: str):
        """Update finding status (open, fixed, acknowledged)."""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        self.conn.commit()