"""Database schema initialization and connection management."""

import sqlite3
import os
from pathlib import Path
from contextlib import contextmanager
from typing import Generator, Optional


DATABASE_PATH = os.environ.get("SHIPCHECK_DB_PATH", "shipcheck.db")


def get_db_path() -> str:
    return DATABASE_PATH


def init_db() -> None:
    """Initialize the database schema if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    # Projects table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scan_at TIMESTAMP,
            project_context TEXT  -- JSON string with detected tech
        )
    """)

    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',  -- queued, running, completed, failed
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            summary TEXT,  -- JSON string
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            file_path TEXT,
            line_number INTEGER,
            confidence TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'open',  -- open, fixed, acknowledged
            first_detected_scan TEXT,
            last_detected_scan TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)

    # Hindsight memory table (developer decisions, notes, intentional exceptions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hindsight_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            finding_id TEXT,
            type TEXT NOT NULL,  -- note, exception, decision
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
        )
    """)

    conn.commit()
    conn.close()


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database connections."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_connection() -> sqlite3.Connection:
    """Get a raw database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def get_project_dir(project_id: str) -> Path:
    """Get the project directory path."""
    base = Path(os.environ.get("SHIPCHECK_PROJECTS_DIR", "./projects"))
    base.mkdir(exist_ok=True)
    return base / project_id