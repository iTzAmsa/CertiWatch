import sqlite3
from pathlib import Path
from typing import Sequence

DB_PATH = Path(__file__).resolve().parent / "certiwatch.db"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT,
    target TEXT,
    port INTEGER,
    issuer TEXT,
    expiry_date TEXT,
    days_remaining INTEGER,
    is_valid TEXT,
    weak_protocols TEXT,
    weak_ciphers TEXT,
    security_status TEXT,
    scan_duration_sec REAL
)
"""

INSERT_SQL = """
INSERT INTO scan_results (
    scan_time, target, port, issuer, expiry_date, days_remaining,
    is_valid, weak_protocols, weak_ciphers, security_status,
    scan_duration_sec
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _connect() -> sqlite3.Connection:
    """Open the project database with a reasonable lock timeout."""
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def init_db() -> None:
    """Create the database and scan_results table when they do not exist."""
    connection = _connect()
    try:
        connection.execute(CREATE_TABLE_SQL)
        connection.commit()
    finally:
        connection.close()


def insert_result(record: Sequence[object]) -> None:
    """Insert one scan record in the column order used by main.py."""
    if len(record) != 11:
        raise ValueError(
            f"A scan record must contain 11 values; received {len(record)}."
        )

    connection = _connect()
    try:
        connection.execute(INSERT_SQL, tuple(record))
        connection.commit()
    finally:
        connection.close()
