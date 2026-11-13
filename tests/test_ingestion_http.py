import base64
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from ingestion.scanners import Approval,Verdict,Blocked,fingerprint
from ingestion.server import handler
from relay.server import BoundedServer

class IngestionHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        class Gate:
            def check(inner,path,name):
                if path.read_bytes()==b'blocked':raise Blocked('malware_detected','clamav')
                if path.read_bytes()==b'offline':raise Blocked('scanner_unavailable','lmd-native')
                sha,size=fingerprint(path);return Approval(sha,size,tuple(Verdict(n,'test','test',sha) for n in ('clamav','lmd-native')))
        self.server=BoundedServer(('127.0.0.1',0),handler(self.root,'s'*64,lambda work:Gate()))
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,body,authorized=True):
        client=http.client.HTTPConnection(*self.server.server_address,timeout=5)
        headers={'X-NextShuttle-Name':base64.b64encode(b'fixture.txt').decode()}
        if authorized:headers['Authorization']='Bearer '+'s'*64
        client.request('POST','/ingestion/v1/scan',body,headers);r=client.getresponse();result=r.status,json.loads(r.read());client.close();return result
    def test_service_authentication_quarantine_cleanup_and_two_verdicts(self):
        self.assertEqual(self.request(b'content',False)[0],401)
        status,data=self.request(b'content');self.assertEqual(status,200);self.assertEqual(len(data['verdicts']),2)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_detections_reject_but_outages_remain_retryable(self):
        self.assertEqual(self.request(b'blocked')[0],422)
        self.assertEqual(self.request(b'offline')[0],503)
        self.assertEqual(list(self.root.iterdir()),[])
