import sqlite3
import json
from pathlib import Path
from banshee.core.events import SecurityEvent
from banshee.core.types import SecurityDecision, _utcnow

class AuditTrail:
    """
    Immutable, queryable SQLite ledger of all security decisions and contexts
    for advanced Forensics and Incident Reconstruction.
    """
    def __init__(self, db_path: str = "banshee_audit.db"):
        self.db_path = Path(db_path)
        self._initialize_db()
        
    def _initialize_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    decision_action TEXT NOT NULL,
                    aggregate_risk TEXT NOT NULL,
                    reasons TEXT,
                    event_payload TEXT
                )
            ''')
            # Create indexes for forensics
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_id ON audit_events(event_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk ON audit_events(aggregate_risk)')
            conn.commit()
            
    def record(self, event: SecurityEvent, decision: SecurityDecision) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_events 
                (timestamp, event_id, event_category, event_action, decision_action, aggregate_risk, reasons, event_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                _utcnow().isoformat(),
                str(event.event_id),
                event.category.value if hasattr(event.category, 'value') else event.category,
                event.action,
                decision.action.value if hasattr(decision.action, 'value') else decision.action,
                decision.aggregate_risk.value if hasattr(decision.aggregate_risk, 'value') else decision.aggregate_risk,
                json.dumps(decision.reasons),
                json.dumps(event.payload, default=str)
            ))
            conn.commit()

    def query_timeline(self, start_time: str, end_time: str):
        """Reconstruct incident timeline (Forensics interface)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM audit_events 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp ASC
            ''', (start_time, end_time))
            return [dict(row) for row in cursor.fetchall()]
