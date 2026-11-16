"""Bounded durable audit journal. No untrusted free text or request credentials."""
import re
import secrets

from relay.store import Rejected


KINDS = frozenset({
    "download_created", "download_ready", "download_claimed", "download_served",
    "download_interrupted", "inbox_created", "upload_reserved", "upload_received",
    "upload_interrupted", "transfer_revoked", "password_rotated", "transfer_expired",
    "page_accessed", "access_denied", "wrong_code", "request_rejected", "rate_limited",
    "service_error", "malware_detected", "content_rejected", "scan_unavailable",
    "upload_imported", "scan_clean",
    "download_retried", "admin_page_accessed", "audit_pruned", "policy_changed", "credentials_rotated", "cleanup_requested",
    "scanner_recovered", "admin_logged_in", "admin_logged_out",
})
SCANNER_KINDS = frozenset({"malware_detected", "content_rejected", "scan_unavailable", "upload_imported", "scan_clean", "policy_changed", "credentials_rotated", "service_error", "page_accessed", "scanner_recovered"})


def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred INTEGER NOT NULL,
        kind TEXT NOT NULL, object_id TEXT, parent_id TEXT,
        severity TEXT NOT NULL, bytes INTEGER);
    CREATE TABLE IF NOT EXISTS audit_state (
        id INTEGER PRIMARY KEY CHECK(id=1), acknowledged INTEGER NOT NULL);
    INSERT OR IGNORE INTO audit_state VALUES (1, 0);
    CREATE TABLE IF NOT EXISTS audit_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')
    columns={row[1] for row in db.execute('PRAGMA table_info(audit_events)')}
    for name in ('client_ip','country','ip_source','country_status'):
        if name not in columns:db.execute('ALTER TABLE audit_events ADD COLUMN '+name+' TEXT')
    db.execute("INSERT OR IGNORE INTO audit_meta VALUES ('journal_id', ?)", (secrets.token_hex(16),))


def append(db, now, kind, object_id=None, parent_id=None, severity="info", size=None, visitor=None):
    if kind not in KINDS or severity not in ("info", "warning", "critical"):
        raise Rejected(400, "Unsupported event")
    for ident in (object_id, parent_id):
        if ident is not None and (not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{32}", ident)):
            raise Rejected(400, "Invalid event object")
    if size is not None and (type(size) is not int or not 0 <= size <= 2**40):
        raise Rejected(400, "Invalid event size")
    if db.execute("SELECT count(*) FROM audit_events").fetchone()[0] >= 100000:
        # Never silently drop events. Operator export/retention is required.
        raise Rejected(507, "Audit journal full")
    visitor=visitor or {}
    result = db.execute("INSERT INTO audit_events (occurred,kind,object_id,parent_id,severity,bytes,client_ip,country,ip_source,country_status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (now,kind,object_id,parent_id,severity,size,visitor.get('client_ip'),visitor.get('country'),visitor.get('ip_source'),visitor.get('country_status')))
    return result.lastrowid


def read(db, after, limit=100):
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise Rejected(400, "Invalid event cursor")
    events = [dict(row) for row in db.execute("SELECT * FROM audit_events WHERE sequence>? ORDER BY sequence LIMIT ?", (after, limit))]
    high = db.execute("SELECT coalesce(max(sequence),0) FROM audit_events").fetchone()[0]
    if after > high:
        raise Rejected(409, "Event cursor is ahead of this journal")
    return {"events": events, "next": events[-1]["sequence"] if events else after,
            "journal_id": db.execute("SELECT value FROM audit_meta WHERE name='journal_id'").fetchone()[0],
            "high_water": high, "acknowledged": db.execute("SELECT acknowledged FROM audit_state WHERE id=1").fetchone()[0]}


def acknowledge(db, through):
    if type(through) is not int or through < 0:
        raise Rejected(400, "Invalid event cursor")
    high = db.execute("SELECT coalesce(max(sequence),0) FROM audit_events").fetchone()[0]
    if through > high:
        raise Rejected(409, "Cannot acknowledge unseen events")
    db.execute("UPDATE audit_state SET acknowledged=max(acknowledged,?) WHERE id=1", (through,))
    # Acknowledgement does not delete the audit history.
    return {"acknowledged": db.execute("SELECT acknowledged FROM audit_state WHERE id=1").fetchone()[0]}
