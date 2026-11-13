"""Two disjoint HTTP applications behind an existing HTTPS reverse proxy."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import signal
import threading
from urllib.parse import urlsplit

from relay.store import Rejected, Store


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


def handler(store, mode, service_token, public_url):
    origin = urlsplit(public_url)
    public_origin = f"{origin.scheme}://{origin.netloc}"
    prefix = origin.path.rstrip("/") + "/api/v1/" if mode == "public" else "/api/v1/"

    class Handler(BaseHTTPRequestHandler):
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

        def headers_out(self, status, length, content_type="application/json"):
            self.response_started = True
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("Connection", "close")
            self.end_headers()

        def respond(self, data, status=200):
            body = json.dumps(data, separators=(",", ":")).encode()
            self.headers_out(status, len(body))
            self.wfile.write(body)

        def token(self):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Bearer ") or len(value) > 512:
                return ""
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
            store.rate(self.client_address[0], scope=mode)
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment or not parsed.path.startswith(prefix):
                raise Rejected()
            path = parsed.path[len(prefix):]
            if "%" in path or "//" in path:
                raise Rejected()
            if mode == "private":
                if not hmac.compare_digest(self.token(), service_token):
                    raise Rejected(401, "Authentication required")
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
                    sequence = store.event(data["kind"], data.get("object_id"), data.get("parent_id"),
                        "critical" if data["kind"] == "malware_detected" else "warning" if data["kind"] in ("content_rejected", "scan_unavailable") else "info")
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
                match = re.fullmatch(r"downloads/([a-f0-9]{32})/fetch", path)
                if method == "POST" and match:
                    if self.content_length(0) != 0:
                        raise Rejected(400)
                    return self.send_blob("download", match[1])
                match = re.fullmatch(r"inboxes/([a-f0-9]{32})/uploads", path)
                if method == "POST" and match:
                    data = self.body()
                    return self.respond(store.reserve_upload(match[1], data.get("password"), data.get("bytes")), 201)
                match = re.fullmatch(r"uploads/([a-f0-9]{32})/blob", path)
                if method == "PUT" and match:
                    store.write("upload", match[1], self.rfile, self.content_length(store.max_blob), self.token())
                    return self.respond({"ok": True})
            raise Rejected()

        def send_blob(self, kind, ident):
            handle, length = store.fetch(kind, ident, self.token())
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
            try:
                parsed = urlsplit(self.path)
                if mode == "public" and self.command == "GET" and parsed.path in (origin.path, origin.path.rstrip("/")):
                    store.rate(self.client_address[0], scope=mode)
                    store.event("page_accessed")
                    return self.respond({"service": "NextShuttle", "status": "development", "transfer_ui_ready": False})
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

        do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = request

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("public", "private"), required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    token = ""
    if args.mode == "private":
        token_path = os.environ.get("NEXTSHUTTLE_SERVICE_TOKEN_FILE", "/run/secrets/service_token")
        token = Path(token_path).read_text().strip()
        if len(token) < 43 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise SystemExit("Service token must be at least 43 random URL-safe characters")
    store = Store(os.environ.get("NEXTSHUTTLE_DATA", "/data"),
                  capacity=int(os.environ.get("NEXTSHUTTLE_CAPACITY", 1024**3)),
                  max_blob=int(os.environ.get("NEXTSHUTTLE_MAX_BLOB", 32*1024**2)))
    public_url = os.environ.get("NEXTSHUTTLE_PUBLIC_URL", "https://helios-public.tail43e437.ts.net/nextshuttle/")
    parsed = urlsplit(public_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise SystemExit("Public URL must be an HTTPS origin with an optional base path")
    server = BoundedServer((args.bind, args.port), handler(store, args.mode, token, public_url))
    stopped = threading.Event()

    def stop(*_):
        stopped.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    def cleanup():
        while not stopped.wait(60):
            store.cleanup()

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
