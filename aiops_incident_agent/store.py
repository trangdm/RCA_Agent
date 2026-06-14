"""Small SQLite store for analyzed synthetic incidents."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any


DEFAULT_STORE_PATH = Path("data/incidents.sqlite3")


def _store_path() -> Path:
    return Path(os.getenv("AIOPS_STORE_PATH", str(DEFAULT_STORE_PATH)))


def _connect() -> sqlite3.Connection:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            severity TEXT,
            root_cause TEXT,
            confidence INTEGER,
            status TEXT,
            incident_json TEXT NOT NULL,
            assessment_json TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def save_assessment(incident: dict[str, Any], assessment: dict[str, Any]) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect()
        cursor = connection.execute(
            """
            INSERT INTO incidents (
                incident_id, created_at, severity, root_cause, confidence, status,
                incident_json, assessment_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(incident.get("incident_id", "")),
                created_at,
                str(assessment.get("severity", "")),
                str(assessment.get("most_likely_root_cause", "")),
                int(assessment.get("confidence") or 0),
                str(assessment.get("status", "")),
                json.dumps(incident, ensure_ascii=False),
                json.dumps(assessment, ensure_ascii=False),
            ),
        )
        connection.commit()
        return {"saved": True, "store_path": str(_store_path()), "row_id": cursor.lastrowid}
    except Exception as exc:  # pragma: no cover - defensive store path
        return {"saved": False, "reason": str(exc), "store_path": str(_store_path())}
    finally:
        if connection is not None:
            connection.close()


def latest_assessment() -> dict[str, Any]:
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect()
        row = connection.execute(
            """
            SELECT incident_json, assessment_json, created_at
            FROM incidents
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return {"found": False}
        return {
            "found": True,
            "incident": json.loads(row[0]),
            "assessment": json.loads(row[1]),
            "created_at": row[2],
        }
    except Exception as exc:  # pragma: no cover - defensive store path
        return {"found": False, "reason": str(exc), "store_path": str(_store_path())}
    finally:
        if connection is not None:
            connection.close()
