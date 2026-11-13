"""Loopback-only browser fixture. Synthetic transfers; no production settings."""
import signal
import tempfile
import threading
from relay.store import Store
from relay.server import BoundedServer,handler
with tempfile.TemporaryDirectory(prefix='nextshuttle-browser-') as directory:
    store=Store(directory,max_blob=34*1024**2)
    servers=[BoundedServer(('127.0.0.1',port),handler(store,mode,'r'*64,'http://127.0.0.1:9084/nextshuttle/','a'*64 if mode=='private' else None,'http://127.0.0.1:9085'))
             for port,mode in ((9084,'public'),(9085,'private'))]
    for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
    stopped=threading.Event()
    def stop(*args):
        for server in servers:server.shutdown();server.server_close()
        stopped.set()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    stopped.wait()
