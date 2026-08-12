import sqlite3
from contextlib import contextmanager

DB_PATH = "data/soc.db"


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                location TEXT,
                country TEXT,
                severity TEXT DEFAULT 'INFO',
                UNIQUE(timestamp, username, ip_address, event_type)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                status TEXT DEFAULT 'NEW',
                details TEXT
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")

def insert_events(records):
    with get_connection() as conn:
        cursor = conn.executemany(
            """
            INSERT OR IGNORE INTO events
                (timestamp, username, ip_address, event_type, status, location, country)
            VALUES (:timestamp, :username, :ip, :event_type, :status, :location, :country)
            """,
            records,
        )
        return cursor.rowcount
def insert_alert(rule_name, triggered_at, severity, username=None, ip_address=None,
                  mitre_technique_id=None, mitre_technique_name=None, details=None):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts
                (rule_name, triggered_at, severity, username, ip_address,
                 mitre_technique_id, mitre_technique_name, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rule_name, triggered_at, severity, username, ip_address,
             mitre_technique_id, mitre_technique_name, details),
        )
        return cursor.lastrowid
def get_event_count():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
def get_alert_count():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")

ALERT_STATUSES = ["NEW", "INVESTIGATING", "FALSE POSITIVE", "RESOLVED"]

def update_alert_status(alert_id, new_status):
    if new_status not in ALERT_STATUSES:
        raise ValueError(
            f"Invalid status '{new_status}'. Must be one of {ALERT_STATUSES}."
        )

    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (new_status, alert_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"No alert found with id {alert_id}.")
        return True
def get_alert(alert_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None