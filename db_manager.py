import sqlite3

DB_NAME = "certiwatch.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
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
    """)
    conn.commit()
    conn.close()


def insert_result(record):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_results (
            scan_time, target, port, issuer, expiry_date, days_remaining,
            is_valid, weak_protocols, weak_ciphers, security_status, scan_duration_sec
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, record)
    conn.commit()
    conn.close()
