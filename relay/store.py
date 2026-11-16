"""Bounded opaque storage. No plaintext, encryption keys, or Nextcloud credentials.

Storage names come only from generated IDs. SQLite write transactions serialize
reservations, counters and state changes across both listener processes.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time


HASH_SLOTS = threading.BoundedSemaphore(4)


class Rejected(Exception):
    def __init__(self, status=404, message="Transfer unavailable", audit_kind=None):
        self.status, self.message = status, message
        self.audit_kind = audit_kind


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password, salt, *, legacy=False):
    if not isinstance(password, str) or not 16 <= len(password) <= 256:
        raise Rejected(400, "Password must contain 16 to 256 characters")
    if not HASH_SLOTS.acquire(blocking=False):
        raise Rejected(429, "Password verification busy")
    try:
        raw=hashlib.scrypt(password.encode(),salt=salt,n=16384 if legacy else 32768,r=8,p=1 if legacy else 3,maxmem=64*1024**2).hex()
        return raw if legacy else 'scrypt:32768:8:3:'+raw
    finally:
        HASH_SLOTS.release()


class Store:
    def __init__(self, directory, *, capacity=1024**3, max_blob=32*1024**2,
                 max_ttl=7*86400, retention=7*86400, clock=time.time):
        self.visitor=ContextVar('nextshuttle_visitor',default={})
        self.root = Path(directory)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.capacity, self.max_blob = capacity, max_blob
        self.max_ttl, self.retention, self.clock = max_ttl, retention, clock
        self.db = self.root / "metadata.sqlite3"
        with self.tx() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS downloads (
                id TEXT PRIMARY KEY, credential TEXT NOT NULL,
                bytes INTEGER NOT NULL, expires INTEGER NOT NULL,
                max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL, created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS inboxes (
                id TEXT PRIMARY KEY, salt BLOB NOT NULL, password TEXT NOT NULL,
                public_key TEXT NOT NULL, expires INTEGER NOT NULL,
                max_bytes INTEGER NOT NULL, max_files INTEGER NOT NULL,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                used_files INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY, inbox TEXT NOT NULL, credential TEXT NOT NULL,
                bytes INTEGER NOT NULL, expires INTEGER NOT NULL,
                state TEXT NOT NULL, created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS rate_limits (
                bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
            ''')
            from relay import audit
            audit.initialize(db)
        with self.tx() as db:
            if 'password' not in {row[1] for row in db.execute('PRAGMA table_info(downloads)')}:
                db.execute("ALTER TABLE downloads ADD COLUMN password TEXT NOT NULL DEFAULT ''")

    def event(self, kind, ident=None, parent=None, severity="info", size=None, db=None):
        from relay.audit import append
        if db is not None:
            return append(db, self.now(), kind, ident, parent, severity, size, self.visitor.get())
        with self.tx() as connection:
            return append(connection, self.now(), kind, ident, parent, severity, size, self.visitor.get())

    def events(self, after=0, limit=100):
        from relay.audit import read
        with self.tx() as db:
            return read(db, after, limit)

    def acknowledge(self, through):
        from relay.audit import acknowledge
        with self.tx() as db:
            return acknowledge(db, through)

    def reset_download(self, ident):
        self.valid_id(ident)
        with self.tx() as db:
            row=db.execute('SELECT * FROM downloads WHERE id=?',(ident,)).fetchone()
            if not row or row['expires']<=self.now() or row['state']!='failed' or row['uses']:
                raise Rejected(409,'Download is not retryable')
            self.blob(ident).unlink(missing_ok=True)
            db.execute("UPDATE downloads SET state='pending' WHERE id=?",(ident,))
            self.event('download_retried',ident,db=db)

    def prune_audit(self, before):
        self.integer(before,0,self.now())
        with self.tx() as db:
            ack=db.execute('SELECT acknowledged FROM audit_state WHERE id=1').fetchone()[0]
            count=db.execute('DELETE FROM audit_events WHERE sequence<=? AND occurred<?',(ack,before)).rowcount
            db.execute("DELETE FROM audit_meta WHERE name LIKE 'report:%' AND NOT EXISTS (SELECT 1 FROM audit_events WHERE sequence=CAST(json_extract(audit_meta.value,'$.sequence') AS INTEGER))")
            if count:self.event('audit_pruned',db=db)
        return {'removed':count}

    def export_events(self,after):
        rows=[]
        for _ in range(10):
            batch=self.events(after,100);rows.extend(batch['events']);after=batch['next']
            if after>=batch['high_water']:break
        return {**batch,'events':rows}

    def report_event(self,data):
        import json
        event_id=data.get('event_id')
        if event_id is not None:self.valid_id(event_id)
        occurred=data.get('occurred')
        if occurred is not None:self.integer(occurred,0,self.now()+60)
        payload=[data['kind'],data.get('object_id'),data.get('parent_id'),occurred]
        with self.tx() as db:
            if event_id:
                old=db.execute('SELECT value FROM audit_meta WHERE name=?',('report:'+event_id,)).fetchone()
                if old:
                    saved=json.loads(old[0])
                    if saved['payload']!=payload:raise Rejected(409,'Audit report ID conflict')
                    return saved['sequence']
            severity='critical' if data['kind']=='malware_detected' else 'warning' if data['kind'] in ('content_rejected','scan_unavailable','service_error') else 'info'
            from relay.audit import append
            sequence=append(db,self.now() if occurred is None else occurred,data['kind'],data.get('object_id'),data.get('parent_id'),severity)
            if event_id:db.execute('INSERT INTO audit_meta VALUES (?,?)',('report:'+event_id,json.dumps({'payload':payload,'sequence':sequence})))
            return sequence

    @contextmanager
    def tx(self):
        db = sqlite3.connect(self.db, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def now(self):
        return int(self.clock())

    def valid_id(self, value):
        if not isinstance(value,str) or not re.fullmatch(r"[a-f0-9]{32}", value):
            raise Rejected()
        return value

    def blob(self, ident):
        return self.root / (self.valid_id(ident) + ".blob")

    def integer(self, value, low, high):
        if type(value) is not int or not low <= value <= high:
            raise Rejected(400, "Invalid numeric limit")
        return value

    def ttl(self, value):
        return self.now() + self.integer(value, 60, self.max_ttl)

    def expiry(self, data):
        if 'expires' in data:
            return self.integer(data['expires'], self.now()+1, self.now()+self.max_ttl)
        return self.ttl(data.get('ttl'))

    def size(self, value):
        return self.integer(value, 1, self.max_blob)

    def available(self, db, size):
        total = db.execute('''SELECT
            (SELECT coalesce(sum(bytes),0) FROM downloads WHERE state != 'deleted') +
            (SELECT coalesce(sum(bytes),0) FROM uploads WHERE state != 'deleted')''').fetchone()[0]
        count = db.execute('''SELECT (SELECT count(*) FROM downloads) +
            (SELECT count(*) FROM uploads) + (SELECT count(*) FROM inboxes)''').fetchone()[0]
        if total + size > self.capacity or count >= 10000:
            raise Rejected(507, "Relay capacity reached")

    def rate(self, source, limit=30, seconds=60, scope="default"):
        # Include a global budget so changing client addresses cannot bypass all limits.
        window = self.now() // seconds
        denied = False
        with self.tx() as db:
            db.execute("DELETE FROM rate_limits WHERE window < ?", (window-2,))
            for bucket, budget in ((digest(scope+":"+source), limit), ("global:"+scope, limit*20)):
                db.execute('''INSERT INTO rate_limits VALUES (?, ?, 1)
                    ON CONFLICT(bucket) DO UPDATE SET
                    count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END,
                    window=excluded.window''', (bucket, window))
                if db.execute("SELECT count FROM rate_limits WHERE bucket=?", (bucket,)).fetchone()[0] > budget:
                    denied = True
        if denied:
            raise Rejected(429, "Too many requests")

    def create_download(self, data):
        import json
        size, expiry = self.size(data.get("bytes")), self.expiry(data)
        uses = self.integer(data.get("max_uses", 1), 1, 1000)
        ident, token = self.valid_id(data.get('id',secrets.token_hex(16))), data.get('access_token',secrets.token_urlsafe(32))
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}',token):
            raise Rejected(400,'Invalid access credential')
        protection=''
        if data.get('password'):
            salt=secrets.token_bytes(16)
            protection=json.dumps({'salt':salt.hex(),'hash':password_hash(data['password'],salt)})
        with self.tx() as db:
            old=db.execute('SELECT * FROM downloads WHERE id=?',(ident,)).fetchone()
            if old:
                if old['bytes']!=size or old['expires']!=expiry or old['max_uses']!=uses or not hmac.compare_digest(old['credential'],digest(token)):
                    raise Rejected(409,'Transfer ID already used')
                if bool(old['password'])!=bool(protection):raise Rejected(409,'Download protection changed')
                if old['password']:
                    saved=json.loads(old['password'])
                    if not hmac.compare_digest(saved['hash'],password_hash(data.get('password'),bytes.fromhex(saved['salt']))):raise Rejected(409,'Download protection changed')
                return {'id':ident,'access_token':token,'expires':expiry,'state':old['state']}
            self.available(db, size)
            db.execute("INSERT INTO downloads(id,credential,bytes,expires,max_uses,uses,state,created,password) VALUES (?, ?, ?, ?, ?, 0, 'pending', ?, ?)",
                       (ident, digest(token), size, expiry, uses, self.now(),protection))
            self.event("download_created", ident, size=size, db=db)
        return {"id": ident, "access_token": token, "expires": expiry}

    def create_inbox(self, data):
        import base64
        key = data.get("public_key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 32:
                raise ValueError()
        except (ValueError, TypeError):
            raise Rejected(400, "Expected a base64 sodium box public key")
        expiry = self.expiry(data)
        size = self.integer(data.get("max_bytes"), 1, self.capacity)
        files = self.integer(data.get("max_files", 10), 1, 1000)
        salt, ident = secrets.token_bytes(16), self.valid_id(data.get('id',secrets.token_hex(16)))
        hashed = password_hash(data.get("password"), salt)
        with self.tx() as db:
            old=db.execute('SELECT * FROM inboxes WHERE id=?',(ident,)).fetchone()
            if old:
                if old['revoked'] or old['public_key']!=key or old['expires']!=expiry or old['max_bytes']!=size or old['max_files']!=files or not hmac.compare_digest(old['password'],password_hash(data.get('password'),old['salt'],legacy=not old['password'].startswith('scrypt:'))):
                    raise Rejected(409,'Inbox ID already used')
                return {'id':ident,'expires':expiry}
            self.available(db, 0)
            db.execute("INSERT INTO inboxes VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0)",
                       (ident, salt, hashed, key, expiry, size, files))
            self.event("inbox_created", ident, db=db)
        return {"id": ident, "expires": expiry}

    def reserve_upload(self, inbox, password, size):
        self.valid_id(inbox)
        size = self.size(size)
        # Fetch before expensive hashing; no SQLite write lock while scrypt runs.
        with self.tx() as db:
            row = db.execute("SELECT * FROM inboxes WHERE id=?", (inbox,)).fetchone()
        if not row or row["revoked"] or row["expires"] <= self.now():
            raise Rejected()
        try:
            hashed = password_hash(password, row["salt"],legacy=not row['password'].startswith('scrypt:'))
        except Rejected:
            raise Rejected(audit_kind="wrong_code")
        if not hmac.compare_digest(hashed, row["password"]):
            raise Rejected(audit_kind="wrong_code")
        ident, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        with self.tx() as db:
            current = db.execute("SELECT * FROM inboxes WHERE id=?", (inbox,)).fetchone()
            if (not current or current["revoked"] or current["expires"] <= self.now()
                    or current["password"] != hashed):
                raise Rejected()
            if current["used_files"] >= current["max_files"] or current["used_bytes"]+size > current["max_bytes"]:
                raise Rejected(413, "Inbox limit reached")
            self.available(db, size)
            db.execute("UPDATE inboxes SET used_files=used_files+1, used_bytes=used_bytes+? WHERE id=?", (size, inbox))
            expiry = min(current["expires"], self.now()+900)
            db.execute("INSERT INTO uploads VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                       (ident, inbox, digest(token), size, expiry, self.now()))
            self.event('page_accessed',inbox,db=db)
            self.event("upload_reserved", ident, inbox, size=size, db=db)
        return {"id": ident, "upload_token": token, "public_key": row["public_key"],
                "expires": expiry, "bytes": size}

    def view_download(self,ident,token):
        self.valid_id(ident)
        with self.tx() as db:
            row=db.execute('SELECT * FROM downloads WHERE id=?',(ident,)).fetchone()
            if not row or row['state']!='ready' or row['expires']<=self.now():raise Rejected()
            if not hmac.compare_digest(digest(token or ''),row['credential']):raise Rejected(audit_kind='wrong_code')
            self.event('page_accessed',ident,db=db)
            return {'available':row['uses']<row['max_uses'],'expires':row['expires'],'requires_password':bool(row['password'])}

    def view_inbox(self,ident,public_key):
        self.valid_id(ident)
        if not isinstance(public_key,str) or len(public_key)>64:raise Rejected(400,'Invalid inbox code')
        try:key=public_key.encode('ascii')
        except UnicodeError:raise Rejected(400,'Invalid inbox code')
        with self.tx() as db:
            row=db.execute('SELECT * FROM inboxes WHERE id=?',(ident,)).fetchone()
            if not row or row['revoked'] or row['expires']<=self.now():raise Rejected()
            if not hmac.compare_digest(key,row['public_key'].encode('ascii')):raise Rejected(audit_kind='wrong_code')
            self.event('page_accessed',ident,db=db)
            return {'available':True,'expires':row['expires'],'requires_password':True}

    def write(self, kind, ident, stream, length, token=None):
        self.valid_id(ident)
        table = "downloads" if kind == "download" else "uploads"
        temporary = self.root / (ident + "." + secrets.token_hex(8) + ".part")
        with self.tx() as db:
            row = db.execute(f"SELECT * FROM {table} WHERE id=?", (ident,)).fetchone()
            if not row or row["state"] != "pending" or row["expires"] <= self.now():
                raise Rejected()
            if table == "uploads" and not hmac.compare_digest(digest(token or ""), row["credential"]):
                raise Rejected(audit_kind="wrong_code")
            if type(length) is not int or length != row["bytes"]:
                raise Rejected(400, "Ciphertext length does not match reservation")
            db.execute(f"UPDATE {table} SET state='writing' WHERE id=?", (ident,))
        try:
            with temporary.open("xb") as out:
                remaining = length
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise Rejected(400, "Incomplete ciphertext")
                    out.write(chunk)
                    remaining -= len(chunk)
                out.flush()
                os.fsync(out.fileno())
            with self.tx() as db:
                current = db.execute(f"SELECT * FROM {table} WHERE id=?", (ident,)).fetchone()
                if not current or current["state"] != "writing" or current["expires"] <= self.now():
                    raise Rejected()
                if table == "uploads":
                    inbox = db.execute("SELECT * FROM inboxes WHERE id=?", (current["inbox"],)).fetchone()
                    if not inbox or inbox["revoked"] or inbox["expires"] <= self.now():
                        raise Rejected()
                os.replace(temporary, self.blob(ident))
                expiry = self.now()+self.retention if table == "uploads" else current["expires"]
                db.execute(f"UPDATE {table} SET state='ready', expires=? WHERE id=?", (expiry, ident))
                self.event("download_ready" if table == "downloads" else "upload_received", ident,
                           current["inbox"] if table == "uploads" else None, size=length, db=db)
        except BaseException:
            # Cleanup never releases reserved capacity until the disk object is gone.
            with self.tx() as db:
                db.execute(f"UPDATE {table} SET state='failed' WHERE id=? AND state='writing'", (ident,))
                self.event("upload_interrupted" if table == "uploads" else "service_error", ident,
                           row["inbox"] if table == "uploads" else None, severity="warning", db=db)
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def fetch(self, kind, ident, token=None, password=None):
        self.valid_id(ident)
        table = "downloads" if kind == "download" else "uploads"
        with self.tx() as db:
            row = db.execute(f"SELECT * FROM {table} WHERE id=?", (ident,)).fetchone()
            if not row or row["state"] != "ready" or row["expires"] <= self.now():
                raise Rejected()
            if table == "downloads":
                if not hmac.compare_digest(digest(token or ""), row["credential"]):
                    raise Rejected(audit_kind="wrong_code")
                if row["uses"] >= row["max_uses"]:
                    raise Rejected()
                if row['password']:
                    import json
                    saved=json.loads(row['password'])
                    try:valid=hmac.compare_digest(saved['hash'],password_hash(password,bytes.fromhex(saved['salt'])))
                    except Rejected:valid=False
                    if not valid:raise Rejected(audit_kind='wrong_code')
            try:
                handle = self.blob(ident).open("rb")
            except FileNotFoundError:
                raise Rejected()
            if table == "downloads":
                db.execute("UPDATE downloads SET uses=uses+1 WHERE id=?", (ident,))
                try:
                    self.event("download_claimed", ident, size=row["bytes"], db=db)
                except BaseException:
                    handle.close()
                    raise
            return handle, row["bytes"]

    def revoke(self, kind, ident):
        self.valid_id(ident)
        table = {"download": "downloads", "upload": "uploads", "inbox": "inboxes"}[kind]
        with self.tx() as db:
            if table == "inboxes":
                db.execute("UPDATE inboxes SET revoked=1 WHERE id=?", (ident,))
                db.execute("UPDATE uploads SET state='revoked' WHERE inbox=?", (ident,))
            else:
                db.execute(f"UPDATE {table} SET state='revoked' WHERE id=?", (ident,))
            parent = None
            if table == "uploads":
                row = db.execute("SELECT inbox FROM uploads WHERE id=?", (ident,)).fetchone()
                parent = row[0] if row else None
            self.event("transfer_revoked", ident, parent, db=db)

    def rotate_password(self, ident, password):
        self.valid_id(ident)
        salt = secrets.token_bytes(16)
        hashed = password_hash(password, salt)
        with self.tx() as db:
            changed = db.execute("UPDATE inboxes SET salt=?, password=? WHERE id=? AND revoked=0 AND expires>?",
                                 (salt, hashed, ident, self.now())).rowcount
            if not changed:
                raise Rejected()
            # Previously issued upload capabilities are invalid after rotation.
            db.execute("UPDATE uploads SET state='revoked' WHERE inbox=? AND state IN ('pending','writing')", (ident,))
            self.event("password_rotated", ident, db=db)

    def list(self, uploads_only=False):
        with self.tx() as db:
            if uploads_only:
                return [dict(r) for r in db.execute("SELECT id,inbox,bytes,expires,created FROM uploads WHERE state='ready' AND expires>?", (self.now(),))]
            return {"downloads": [dict(r) for r in db.execute("SELECT id,bytes,expires,max_uses,uses,state,created FROM downloads")],
                    "inboxes": [dict(r) for r in db.execute("SELECT id,expires,max_bytes,max_files,used_bytes,used_files,revoked FROM inboxes")],
                    "uploads": [dict(r) for r in db.execute("SELECT id,inbox,bytes,expires,state,created FROM uploads")]}

    def cleanup(self):
        removed = 0
        with self.tx() as db:
            for table in ("downloads", "uploads"):
                rows = db.execute(f'''SELECT * FROM {table} WHERE expires<=?
                    OR state IN ('revoked','failed')
                    OR (state IN ('pending','writing') AND created<=?)''', (self.now(), self.now()-900)).fetchall()
                for row in rows:
                    ident = row["id"]
                    if row["expires"] <= self.now():
                        self.event("transfer_expired", ident, row["inbox"] if table == "uploads" else None, db=db)
                    self.blob(ident).unlink(missing_ok=True)
                    for part in self.root.glob(ident + ".*.part"):
                        part.unlink(missing_ok=True)
                    db.execute(f"DELETE FROM {table} WHERE id=?", (ident,))
                    removed += 1
            db.execute("DELETE FROM inboxes WHERE (expires<=? OR revoked=1) AND id NOT IN (SELECT inbox FROM uploads)", (self.now(),))
            # Recovery after a crash between atomic rename and DB commit.
            known = {r[0] for r in db.execute("SELECT id FROM downloads UNION SELECT id FROM uploads")}
            for path in self.root.glob("*.blob"):
                if path.stem not in known:
                    path.unlink()
        return {"removed": removed}
