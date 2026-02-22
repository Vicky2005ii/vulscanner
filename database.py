import sqlite3

def create_database():
    conn = sqlite3.connect("reports.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY,
            target TEXT,
            vulnerability TEXT,
            details TEXT,
            date TEXT
        )
    """)

    conn.commit()
    conn.close()
