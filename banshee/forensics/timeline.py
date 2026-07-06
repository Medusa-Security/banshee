from typing import List, Dict, Any
from banshee.core.audit import AuditTrail

class TimelineGenerator:
    """
    Reconstructs an incident timeline from the SQLite Audit Trail.
    """
    def __init__(self, db_path: str = "banshee_audit.db"):
        self.audit = AuditTrail(db_path)

    def generate_timeline(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """
        Query the audit trail for events in a specific timeframe.
        """
        return self.audit.query_timeline(start_time, end_time)

    def generate_timeline_by_event(self, event_id: str) -> List[Dict[str, Any]]:
        """
        Query the audit trail for a specific event ID.
        """
        import sqlite3
        timeline = []
        try:
            with sqlite3.connect(self.audit.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM audit_events 
                    WHERE event_id = ?
                    ORDER BY timestamp ASC
                ''', (event_id,))
                timeline = [dict(row) for row in cursor.fetchall()]
        except Exception:
            pass
        return timeline
