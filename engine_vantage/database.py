import json
import sqlite3
from datetime import datetime, timezone


DATABASE = "riskforge.db"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, sort_keys=True)


def _reason(evidence):
    return evidence.get("reason") if isinstance(evidence, dict) else None


def _normalize_result(results):
    if isinstance(results, dict):
        return {
            "target": results.get("target") or "unknown",
            "scan_time": results.get("scan_time") or _utc_now(),
            "ports": results.get("ports", []),
            "findings": results.get("findings", []),
            "indeterminate": results.get("indeterminate", []),
            "lookup_errors": results.get("lookup_errors", []),
        }

    ports = list(results or [])
    return {
        "target": ports[0].get("host", "unknown") if ports else "unknown",
        "scan_time": _utc_now(),
        "ports": ports,
        "findings": [],
        "indeterminate": [],
        "lookup_errors": [],
    }


def initialize_database(database_path=None):
    conn = sqlite3.connect(database_path or DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            state TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            description TEXT,
            cvss REAL,
            severity TEXT,
            weaknesses TEXT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            risk_score REAL,
            risk_level TEXT,
            risk_rank INTEGER,
            applicability_evidence TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS indeterminate_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            description TEXT,
            cvss REAL,
            severity TEXT,
            weaknesses TEXT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            applicability_evidence TEXT,
            reason TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS lookup_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            error TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    return conn


def save_scan_results(results, database_path=None):
    scan = _normalize_result(results)

    conn = initialize_database(database_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO scans (target, scan_time) VALUES (?, ?)",
            (scan["target"], scan["scan_time"]),
        )
        scan_id = cursor.lastrowid

        for port in scan["ports"]:
            cursor.execute(
                """
                INSERT INTO scan_ports
                (scan_id, host, port, protocol, service, product, version, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    port["host"],
                    port["port"],
                    port["protocol"],
                    port.get("service"),
                    port.get("product"),
                    port.get("version"),
                    port["state"],
                ),
            )

        for finding in scan["findings"]:
            cursor.execute(
                """
                INSERT INTO findings
                (
                    scan_id, cve_id, description, cvss, severity, weaknesses,
                    host, port, protocol, service, product, version,
                    risk_score, risk_level, risk_rank, applicability_evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding["cve_id"],
                    finding.get("description"),
                    finding.get("cvss"),
                    finding.get("severity"),
                    _json(finding.get("weaknesses", [])),
                    finding["host"],
                    finding["port"],
                    finding["protocol"],
                    finding.get("service"),
                    finding.get("product"),
                    finding.get("version"),
                    finding.get("risk_score"),
                    finding.get("risk_level"),
                    finding.get("risk_rank"),
                    _json(finding.get("applicability_evidence", {})),
                ),
            )

        for finding in scan["indeterminate"]:
            evidence = finding.get("applicability_evidence", {})
            cursor.execute(
                """
                INSERT INTO indeterminate_findings
                (
                    scan_id, cve_id, description, cvss, severity, weaknesses,
                    host, port, protocol, service, product, version,
                    applicability_evidence, reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding["cve_id"],
                    finding.get("description"),
                    finding.get("cvss"),
                    finding.get("severity"),
                    _json(finding.get("weaknesses", [])),
                    finding["host"],
                    finding["port"],
                    finding.get("protocol"),
                    finding.get("service"),
                    finding.get("product"),
                    finding.get("version"),
                    _json(evidence),
                    _reason(evidence),
                ),
            )

        for error in scan["lookup_errors"]:
            cursor.execute(
                """
                INSERT INTO lookup_errors
                (scan_id, host, port, service, product, version, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    error["host"],
                    error["port"],
                    error.get("service"),
                    error.get("product"),
                    error.get("version"),
                    error["error"],
                ),
            )

        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
