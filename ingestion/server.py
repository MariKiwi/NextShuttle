"""Private, single-job scanning gateway. No Nextcloud credentials or decryption keys."""
from dataclasses import asdict
import base64
from http.server import BaseHTTPRequestHandler
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time

from ingestion.scanners import Blocked, Approval, Verdict, ClamAV, run_bounded
from relay.server import BoundedServer,HardenedHandler


def handler(root, token, gate_factory):
    slot = threading.BoundedSemaphore(1)
    class Handler(HardenedHandler):
        server_version = 'NextShuttle'
        sys_version = ''
        def setup(self):
            super().setup(); self.connection.settimeout(30)
        def log_message(self, *_): pass
        def send_error(self,code,message=None,explain=None):self.reply(code,{'error':'Request rejected'})
        def reply(self, status, data):
            raw = json.dumps(data, separators=(',', ':')).encode()
            self.send_response(status)
            for name, value in [('Content-Type','application/json'),('Content-Length',str(len(raw))),('Cache-Control','no-store'),('Connection','close'),('X-Content-Type-Options','nosniff')]:
                self.send_header(name,value)
            self.end_headers(); self.wfile.write(raw)
        def do_POST(self):
            if self.path != '/ingestion/v1/scan' or self.headers.get('Origin'):
                return self.reply(404, {'error':'Unavailable'})
            if not hmac.compare_digest(self.headers.get('Authorization','').encode(), ('Bearer '+token).encode()):
                return self.reply(401, {'error':'Authentication required'})
            if not slot.acquire(blocking=False):
                return self.reply(503, {'error':'Scanner busy'})
            try:
                sizes=self.headers.get_all('Content-Length',[])
                if len(sizes)!=1 or not re.fullmatch(r'[0-9]{1,9}',sizes[0]) or self.headers.get('Transfer-Encoding'):
                    return self.reply(400,{'error':'Invalid request framing'})
                size=int(sizes[0])
                if not 0<size<=32*1024**2:return self.reply(413,{'error':'File exceeds scanner limit'})
                name=base64.b64decode(self.headers.get('X-NextShuttle-Name',''),validate=True).decode('utf-8')
                if not name or len(name.encode())>240:raise Blocked('unsafe_filename')
                with tempfile.TemporaryDirectory(prefix='job-',dir=root) as work:
                    path=Path(work)/'input'
                    deadline=time.monotonic()+120
                    with path.open('xb') as out:
                        remaining=size
                        while remaining:
                            data=self.rfile.read(min(65536,remaining))
                            if not data or time.monotonic()>deadline:raise Blocked('incomplete_upload')
                            out.write(data);remaining-=len(data)
                    path.chmod(0o400)
                    approval=gate_factory(Path(work)).check(path,name)
                self.reply(200,asdict(approval))
            except Blocked as error:
                transient=any(word in error.reason for word in ('scanner','signatures','scan_incomplete','scan_budget','scan_report'))
                self.reply(503 if transient else 422,{'error':'Scanning unavailable' if transient else 'Upload blocked','reason':error.reason,'engine':error.engine})
            except (ValueError,UnicodeError):
                self.reply(400,{'error':'Invalid request'})
            except (BrokenPipeError,ConnectionResetError,TimeoutError):pass
            except Exception:self.reply(503,{'error':'Scanning unavailable'})
            finally:slot.release()
        def do_GET(self):
            if self.path!='/ingestion/v1/health' or self.headers.get('Origin'):return self.reply(404,{'error':'Unavailable'})
            if not hmac.compare_digest(self.headers.get('Authorization','').encode(),('Bearer '+token).encode()):return self.reply(401,{'error':'Authentication required'})
            try:
                clam=ClamAV('/run/nextshuttle/clamd.sock')
                with clam.connect() as connection:connection.sendall(b'zVERSION\0');version=clam.response(connection)
                from datetime import datetime,timezone
                match=re.fullmatch(r'ClamAV ([^/]+)/([0-9]+)/(.+)',version)
                if not match:raise ValueError()
                updated=datetime.strptime(match[3],'%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
                if not -3600<=time.time()-updated<=48*3600:raise ValueError()
                from ingestion.signatures import verified
                with verified('/usr/local/maldetect/sigs') as age:
                    self.reply(200,{'ready':True,'clamav':match[1],'clamav_signature_age':int(time.time()-updated),'lmd_last_verified_age':age})
            except Exception:self.reply(503,{'ready':False,'error':'Scanner or signature health unavailable'})
    return Handler


def main():
    os.umask(0o077)
    token=Path(os.environ.get('NEXTSHUTTLE_SCANNER_TOKEN_FILE','/run/secrets/scanner_token')).read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{43,256}',token):raise SystemExit('Invalid scanner credential')
    root=Path(os.environ.get('NEXTSHUTTLE_QUARANTINE','/quarantine'));root.mkdir(exist_ok=True)
    state=Path('/usr/local/maldetect/pub/shuttle')
    for folder in ('tmp','sess','quar'):(state/folder).mkdir(parents=True,exist_ok=True,mode=0o700)
    class ProcessGate:
        def __init__(self,work):self.work=work
        def check(self,path,name):
            import sys
            import shutil
            try:code,raw=run_bounded([sys.executable,'-m','ingestion.job',str(self.work),str(path),base64.b64encode(name.encode()).decode()],timeout=165)
            finally:
                state=Path('/usr/local/maldetect/pub/shuttle')
                for child in state.iterdir():
                    if child.is_symlink() or not child.is_dir():child.unlink(missing_ok=True)
                    else:shutil.rmtree(child)
                for folder in ('tmp','sess','quar'):(state/folder).mkdir(mode=0o700)
            result=json.loads(raw)
            if code!=0:raise Blocked(result.get('reason','scanner_error'),result.get('engine'))
            return Approval(result['sha256'],result['bytes'],tuple(Verdict(**v) for v in result['verdicts']))
    factory=ProcessGate
    BoundedServer(('0.0.0.0',8082),handler(root,token,factory)).serve_forever()


if __name__=='__main__':main()
