"""Two disjoint HTTP applications behind an existing HTTPS reverse proxy."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import hashlib
import html
import json
import os
from pathlib import Path
import re
import signal
import threading
from urllib.parse import urlsplit
import http.client

from relay.store import Rejected, Store


class HardenedHandler(BaseHTTPRequestHandler):
    def parse_request(self):
        if len(self.raw_requestline)>4096:
            self.requestline="";self.request_version=self.default_request_version;self.command=None
            self.send_error(414);return False
        original=self.rfile
        class HeadersOnly:
            def __init__(inner):inner.used=0
            def readline(inner,size=-1):
                remaining=8192-inner.used
                line=original.readline(min(size if size>=0 else remaining+1,remaining+1))
                inner.used+=len(line)
                if inner.used>8192:raise http.client.LineTooLong('header section')
                return line
        self.rfile=HeadersOnly()
        try:return super().parse_request()
        finally:self.rfile=original

class BoundedServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        self.pool = ThreadPoolExecutor(max_workers=16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self.pool.submit(self.work, request, address)

    def work(self, request, address):
        try:
            self.finish_request(request, address)
        except Exception:
            # Deliberately no request/header logging.
            pass
        finally:
            self.shutdown_request(request)
            self.slots.release()

    def server_close(self):
        super().server_close()
        self.pool.shutdown(wait=True)


def handler(store, mode, service_token, public_url, admin_password=None,private_origin='https://shuttle.helios.lan',visitors=None):
    from relay.visitor import Visitors
    visitors=visitors or Visitors()
    from relay.admin_sessions import Sessions
    sessions=Sessions(store.now)
    origin = urlsplit(public_url)
    public_origin = f"{origin.scheme}://{origin.netloc}"
    prefix = origin.path.rstrip("/") + "/api/v1/" if mode == "public" else "/api/v1/"

    class Handler(HardenedHandler):
        server_version = "NextShuttle"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(30)

        def log_message(self, *args):
            pass

        def send_error(self, code, message=None, explain=None):
            # Parser/unsupported-method errors bypass dispatch. Never echo their
            # raw request line into logs or into an error document.
            try:
                store.event("request_rejected", severity="warning")
                self.respond({"error": "Request rejected"}, code)
            except (Rejected, BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True

        def headers_out(self, status, length, content_type="application/json",web=False):
            self.response_started = True
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" if web else "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("Connection", "close")
            if getattr(self,'pending_cookie',None):self.send_header('Set-Cookie',self.pending_cookie)
            self.end_headers()

        def respond(self, data, status=200):
            body = json.dumps(data, separators=(",", ":")).encode()
            self.headers_out(status, len(body))
            self.wfile.write(body)

        def static(self, name, csrf=None):
            allowed={'index.html':'text/html; charset=utf-8','public.js':'text/javascript','public.css':'text/css','admin.html':'text/html; charset=utf-8','admin.js':'text/javascript','login.html':'text/html; charset=utf-8','login.js':'text/javascript'}
            if name not in allowed:raise Rejected()
            path=Path(__file__).parent/'static'/name
            if not path.is_file():raise Rejected(503,'Frontend build unavailable')
            raw=path.read_bytes()
            if csrf is not None:raw=raw.replace(b'__CSRF__',html.escape(csrf).encode())
            self.headers_out(200,len(raw),allowed[name],web=True);self.wfile.write(raw)

        def set_session_cookie(self,token,ttl):
            self.pending_cookie=f'{sessions.cookie_name}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={ttl}'

        def admin(self):
            store.rate(self.client_address[0],limit=120,scope='admin')
            parsed=urlsplit(self.path);path=parsed.path
            if parsed.query or parsed.fragment:raise Rejected()
            if self.command=='GET' and path in ('/admin/assets/login.js','/admin/assets/public.css'):
                return self.static(path.rsplit('/',1)[-1])
            token=sessions.token(self.headers.get('Cookie',''));session=sessions.get(token)
            if self.command=='GET' and path=='/' and not (session and session['authenticated']):
                try:token,session,ttl=sessions.create(replace=token)
                except ValueError:raise Rejected(503,'Administration busy')
                self.set_session_cookie(token,ttl);return self.static('login.html',session['csrf'])
            if self.command=='POST':
                if self.headers.get('Origin')!=private_origin:raise Rejected(403,'Private origin required')
                if not session or not hmac.compare_digest(self.headers.get('X-NextShuttle-CSRF',''),session['csrf']):raise Rejected(403,'Reload the administration page')
                if path=='/admin/login':
                    store.rate(self.client_address[0],limit=10,scope='admin-login')
                    password=self.body().get('password')
                    if not isinstance(password,str) or len(password)>256 or not hmac.compare_digest(password.encode(),admin_password.encode()):raise Rejected(401,'Sign in failed')
                    try:store.event('admin_logged_in')
                    except Rejected as error:
                        if error.status!=507:raise
                        print('NextShuttle recovery administrator signed in while audit storage is full',flush=True)
                    try:token,session,ttl=sessions.create(True,replace=token)
                    except ValueError:raise Rejected(503,'Administration busy')
                    self.set_session_cookie(token,ttl);return self.respond({'ok':True})
            if not session or not session['authenticated']:raise Rejected(401,'Sign in required')
            if self.command=='GET':
                if path=='/':
                    try:store.event('admin_page_accessed')
                    except Rejected:pass # Read-only recovery UI must remain reachable if the audit capacity is exhausted.
                    return self.static('admin.html',session['csrf'])
                if path=='/admin/assets/admin.js':return self.static('admin.js')
                if path=='/admin/assets/public.css':return self.static('public.css')
                if path=='/admin/api/state':
                    with store.tx() as db:high=db.execute('SELECT coalesce(max(sequence),0) FROM audit_events').fetchone()[0]
                    return self.respond({'transfers':store.list(),'audit':store.events(max(0,high-100)),'capacity':store.capacity,'max_blob':store.max_blob})
            if self.command!='POST':raise Rejected()
            data=self.body()
            if path=='/admin/logout':
                sessions.remove(token);self.set_session_cookie('',0)
                try:store.event('admin_logged_out')
                except Rejected as error:
                    if error.status!=507:raise
                    print('NextShuttle administrator signed out while audit storage is full',flush=True)
                return self.respond({'ok':True})
            if path=='/admin/api/revoke':
                if data.get('kind') not in ('download','inbox','upload'):raise Rejected(400,'Invalid transfer type')
                store.revoke(data['kind'],data.get('id',''));store.cleanup();return self.respond({'ok':True})
            if path=='/admin/api/password':raise Rejected(409,'Change upload passwords in Nextcloud to keep encryption keys synchronized')
            if path=='/admin/api/cleanup':store.event('cleanup_requested');return self.respond(store.cleanup())
            if path=='/admin/api/export':return self.respond(store.export_events(data.get('after',0)))
            if path=='/admin/api/prune':return self.respond(store.prune_audit(data.get('before')))
            raise Rejected()

        def token(self):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Bearer ") or len(value) > 512:
                return ""
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value[7:]):return ''
            return value[7:]

        def content_length(self, maximum):
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise Rejected(400, "Exactly one Content-Length is required")
            value = self.headers.get("Content-Length", "")
            if not re.fullmatch(r"[0-9]{1,12}", value):
                raise Rejected(400, "Invalid Content-Length")
            length = int(value)
            if length > maximum:
                raise Rejected(413, "Request too large")
            return length

        def body(self):
            if self.headers.get_content_type() != "application/json":
                raise Rejected(415, "Expected application/json")
            length = self.content_length(8192)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise Rejected(400, "Incomplete request")
            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError()
                return data
            except (ValueError, UnicodeError):
                raise Rejected(400, "Invalid JSON object")

        def dispatch(self):
            # No proxy-supplied source address or host is used for authorization.
            if mode=='public':store.rate(self.client_address[0],scope=mode)
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment or not parsed.path.startswith(prefix):
                raise Rejected()
            path = parsed.path[len(prefix):]
            if "%" in path or "//" in path:
                raise Rejected()
            if mode == "private":
                if not hmac.compare_digest(self.token(), service_token):
                    store.rate(self.client_address[0],scope='private-auth')
                    raise Rejected(401, "Authentication required")
                store.rate(self.client_address[0],limit=600,scope='private')
                # This API uses bearer headers, never browser ambient cookies.
                if self.headers.get("Origin"):
                    raise Rejected(403, "Browser management requests are disabled")
            else:
                supplied = self.headers.get("Origin")
                if supplied and supplied != public_origin:
                    raise Rejected(403, "Cross-origin requests are disabled")
                if self.headers.get("Sec-Fetch-Site") == "cross-site":
                    raise Rejected(403, "Cross-site requests are disabled")
            method = self.command
            if mode == "private":
                if method == "POST" and path == "downloads":
                    return self.respond(store.create_download(self.body()), 201)
                if method == "POST" and path == "inboxes":
                    return self.respond(store.create_inbox(self.body()), 201)
                match=re.fullmatch(r'downloads/([a-f0-9]{32})/reset',path)
                if method=='POST' and match:
                    self.body();store.reset_download(match[1]);return self.respond({'ok':True})
                if method == "GET" and path == "transfers":
                    return self.respond(store.list())
                if method == "GET" and path == "uploads":
                    return self.respond(store.list(True))
                if method == "POST" and path == "events/read":
                    data = self.body()
                    return self.respond(store.events(data.get("after", 0), data.get("limit", 100)))
                if method == "POST" and path == "events/ack":
                    return self.respond(store.acknowledge(self.body().get("through")))
                if method == "POST" and path == "events/report":
                    from relay.audit import SCANNER_KINDS
                    data = self.body()
                    if data.get("kind") not in SCANNER_KINDS:
                        raise Rejected(400, "Unsupported ingestion event")
                    sequence = store.report_event(data)
                    return self.respond({"sequence": sequence}, 201)
                if method == "POST" and path == "cleanup":
                    self.body()
                    return self.respond(store.cleanup())
                match = re.fullmatch(r"(downloads|inboxes|uploads)/([a-f0-9]{32})", path)
                if method == "DELETE" and match:
                    kind = {"downloads": "download", "inboxes": "inbox", "uploads": "upload"}[match[1]]
                    store.revoke(kind, match[2])
                    store.cleanup()
                    return self.respond({"ok": True})
                match = re.fullmatch(r"inboxes/([a-f0-9]{32})/password", path)
                if method == "POST" and match:
                    store.rotate_password(match[1], self.body().get("password"))
                    return self.respond({"ok": True})
                match = re.fullmatch(r"downloads/([a-f0-9]{32})/blob", path)
                if method == "PUT" and match:
                    store.write("download", match[1], self.rfile, self.content_length(store.max_blob))
                    return self.respond({"ok": True})
                match = re.fullmatch(r"uploads/([a-f0-9]{32})/blob", path)
                if method == "GET" and match:
                    return self.send_blob("upload", match[1])
            else:
                match=re.fullmatch(r'inboxes/([a-f0-9]{32})/view',path)
                if method=='POST' and match:return self.respond(store.view_inbox(match[1],self.body().get('public_key')))
                match=re.fullmatch(r'downloads/([a-f0-9]{32})/view',path)
                if method=='POST' and match:
                    self.content_length(0);return self.respond(store.view_download(match[1],self.token()))
                match = re.fullmatch(r"downloads/([a-f0-9]{32})/fetch", path)
                if method == "POST" and match:
                    length=self.content_length(8192)
                    password=self.body().get('password') if length else None
                    return self.send_blob("download", match[1],password)
                match = re.fullmatch(r"inboxes/([a-f0-9]{32})/uploads", path)
                if method == "POST" and match:
                    data = self.body()
                    return self.respond(store.reserve_upload(match[1], data.get("password"), data.get("bytes")), 201)
                match = re.fullmatch(r"uploads/([a-f0-9]{32})/blob", path)
                if method == "PUT" and match:
                    store.write("upload", match[1], self.rfile, self.content_length(store.max_blob), self.token())
                    return self.respond({"ok": True})
            raise Rejected()

        def send_blob(self, kind, ident,password=None):
            handle, length = store.fetch(kind, ident, self.token(),password)
            with handle:
                self.headers_out(200, length, "application/octet-stream")
                try:
                    while chunk := handle.read(65536):
                        self.wfile.write(chunk)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, TimeoutError):
                    if kind == "download":
                        store.event("download_interrupted", ident, severity="warning")
                    raise
            if kind == "download":
                # Served bytes != proof a recipient saved/decrypted the file.
                store.event("download_served", ident, size=length)

        def journal_error(self, kind):
            parsed = urlsplit(self.path)
            match = re.fullmatch(re.escape(prefix) + r"(?:downloads|inboxes|uploads)/([a-f0-9]{32})(?:/[a-z]+)?", parsed.path)
            ident = match[1] if match else None
            parent = None
            if ident and "/uploads/" in parsed.path:
                with store.tx() as db:
                    row = db.execute("SELECT inbox FROM uploads WHERE id=?", (ident,)).fetchone()
                    parent = row[0] if row else None
            store.event(kind, ident, parent, severity="warning")

        def request(self):
            self.response_started = False
            self.pending_cookie=None
            context=store.visitor.set(visitors.resolve(self.client_address[0],self.headers) if mode=='public' else {})
            try:
                parsed = urlsplit(self.path)
                if mode=='private' and admin_password and (parsed.path=='/' or parsed.path.startswith('/admin/')):
                    return self.admin()
                if mode=='public' and self.command=='GET' and parsed.path.startswith(origin.path.rstrip('/')+'/assets/'):
                    asset=parsed.path.rsplit('/',1)[-1]
                    if asset not in ('public.js','public.css'):raise Rejected()
                    return self.static(asset)
                if mode == "public" and self.command == "GET" and parsed.path in (origin.path, origin.path.rstrip("/")):
                    store.rate(self.client_address[0], scope=mode)
                    store.event("page_accessed")
                    if parsed.path!=origin.path:
                        self.send_response(308);self.send_header('Location',origin.path);self.send_header('Content-Length','0');self.end_headers();return
                    return self.static('index.html')
                self.dispatch()
            except Rejected as error:
                try:
                    # Polling endpoints do not create audit events recursively.
                    self.journal_error(error.audit_kind or ("rate_limited" if error.status == 429 else "access_denied" if error.status in (401,403,404) else "request_rejected"))
                except Rejected as journal_error:
                    error = journal_error
                if not self.response_started:
                    self.respond({"error": error.message}, error.status)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            except Exception:
                # Do not leak paths, passwords or internal exception details.
                try:
                    self.journal_error("service_error")
                finally:
                    if not self.response_started:
                        self.respond({"error": "Internal relay error"}, 500)

            finally:store.visitor.reset(context)

        do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = request

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("public", "private"), required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    token = ""
    admin_password=None
    if args.mode == "private":
        token_path = os.environ.get("NEXTSHUTTLE_SERVICE_TOKEN_FILE", "/run/secrets/service_token")
        token = Path(token_path).read_text().strip()
        if len(token) < 43 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise SystemExit("Service token must be at least 43 random URL-safe characters")
        admin_password=Path(os.environ.get('NEXTSHUTTLE_ADMIN_PASSWORD_FILE','/run/secrets/admin_password')).read_text().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}',admin_password):raise SystemExit('Invalid private administrator password')
    store = Store(os.environ.get("NEXTSHUTTLE_DATA", "/data"),
                  capacity=int(os.environ.get("NEXTSHUTTLE_CAPACITY", 1024**3)),
                  max_blob=int(os.environ.get("NEXTSHUTTLE_MAX_BLOB", 32*1024**2)))
    public_url = os.environ.get("NEXTSHUTTLE_PUBLIC_URL", "https://helios-public.tail43e437.ts.net/nextshuttle/")
    parsed = urlsplit(public_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise SystemExit("Public URL must be an HTTPS origin with an optional base path")
    from relay.visitor import Visitors
    proxy_file=Path(os.environ.get('NEXTSHUTTLE_PROXY_TOKEN_FILE','/proxy/forwarded_token'))
    proxy_token=''
    if args.mode=='public':
        try:proxy_token=proxy_file.read_text().strip()
        except FileNotFoundError:pass
        except OSError:
            print('Visitor IP forwarding is unverified: proxy token is unreadable; check UID 10001 read permissions',flush=True)
    visitors=Visitors(os.environ.get('NEXTSHUTTLE_TRUSTED_PROXIES',''),proxy_token,os.environ.get('NEXTSHUTTLE_GEOIP_DATABASE','/geoip/country.mmdb'))
    server = BoundedServer((args.bind, args.port), handler(store,args.mode,token,public_url,admin_password,visitors=visitors))
    stopped = threading.Event()

    def stop(*_):
        stopped.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    def cleanup():
        while not stopped.wait(60):
            try:store.cleanup()
            except Exception:print('NextShuttle cleanup unavailable; retrying',flush=True)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if args.mode == "private":
        store.cleanup()
        threading.Thread(target=cleanup, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        stopped.set()
        server.server_close()


if __name__ == "__main__":
    main()
