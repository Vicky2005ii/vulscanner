from results import get_results
import sqlite3
from datetime import datetime

def report_finding(target, vuln_type, severity, details):
    timestamp = datetime.now()

    print("\n-------------------------------")
    print(f"Target      : {target}")
    print(f"Vulnerability: {vuln_type}")
    print(f"Severity    : {severity}")
    print(f"Details     : {details}")
    print(f"Time        : {timestamp}")
    print("-------------------------------\n")

    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            vulnerability TEXT,
            severity TEXT,
            details TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        INSERT INTO findings (target, vulnerability, severity, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (target, vuln_type, severity, details, str(timestamp)))

    conn.commit()
    conn.close()
