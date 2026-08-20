import sqlite3
from datetime import datetime


DATABASE = "riskforge.db"


def save_scan_results(results):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            version TEXT,
            state TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    scanned_at = datetime.now().isoformat(timespec="seconds")

    for result in results:
        cursor.execute("""
            INSERT INTO scan_results
            (host, port, protocol, service, version, state, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["host"],
            result["port"],
            result["protocol"],
            result["service"],
            result["version"],
            result["state"],
            scanned_at
        ))

    conn.commit()
    conn.close()
