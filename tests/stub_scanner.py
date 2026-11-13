"""CI-only transport fixture. Never included in production images or Compose."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        raw=b'{"ready":true}';self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer '+('s'*64):self.send_error(401);return
        data=self.rfile.read(int(self.headers['Content-Length']))
        name=base64.b64decode(self.headers['X-NextShuttle-Name']).decode()
        if b'reject-this-ci-file' in data:
            result={'reason':'malware_detected'};status=422
        else:
            sha=hashlib.sha256(data).hexdigest();result={'sha256':sha,'bytes':len(data),'verdicts':[
                {'engine':engine,'version':'CI-TRANSPORT-FIXTURE','signatures':'fixture','sha256':sha} for engine in ('clamav','lmd-native')]};status=200
        raw=json.dumps(result).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def log_message(self,*args):pass
HTTPServer(('0.0.0.0',8082),Handler).serve_forever()
