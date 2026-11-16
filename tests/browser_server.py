"""Loopback-only browser fixture. Synthetic transfers; no production settings."""
import signal
import tempfile
import threading
import subprocess
import ssl
from pathlib import Path
from relay.store import Store
from relay.server import BoundedServer,handler
with tempfile.TemporaryDirectory(prefix='nextshuttle-browser-') as directory:
    cert=Path(directory)/'cert.pem';key=Path(directory)/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
    store=Store(directory,max_blob=34*1024**2)
    def fixture_handler(mode):
        base=handler(store,mode,'r'*64,'http://127.0.0.1:9084/nextshuttle/','a'*64 if mode=='private' else None,'https://localhost:9085')
        class Fixture(base):
            def do_POST(self):
                if mode=='private' and self.path=='/__fixture/reset-rate-budget' and self.headers.get('Authorization')=='Bearer '+('r'*64):
                    with store.tx() as db:db.execute('DELETE FROM rate_limits')
                    return self.respond({'ok':True})
                return super().do_POST()
        return Fixture
    servers=[BoundedServer(('127.0.0.1',port),fixture_handler(mode)) for port,mode in ((9084,'public'),(9085,'private'))]
    servers[1].socket=tls.wrap_socket(servers[1].socket,server_side=True)
    for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
    stopped=threading.Event()
    def stop(*args):
        for server in servers:server.shutdown();server.server_close()
        stopped.set()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    stopped.wait()
