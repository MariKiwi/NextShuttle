import tempfile
import unittest
from pathlib import Path
from email.message import Message
from types import SimpleNamespace
from relay.visitor import Visitors
class VisitorTests(unittest.TestCase):
    def headers(self,token=None,address=None):
        headers=Message()
        if token is not None:headers['X-NextShuttle-Proxy-Token']=token
        if address is not None:headers['X-NextShuttle-Client-IP']=address
        return headers
    def test_unverified_headers_cannot_spoof_an_address(self):
        token='p'*64;visitor=Visitors('172.19.0.0/16',token)
        for peer,headers in [('172.19.0.2',self.headers(None,'8.8.8.8')),('172.19.0.2',self.headers('wrong','8.8.8.8')),('1.1.1.1',self.headers(token,'8.8.8.8'))]:
            self.assertEqual(visitor.resolve(peer,headers)['client_ip'],peer)
        headers=self.headers(token,'8.8.8.8');headers['X-NextShuttle-Client-IP']='1.1.1.1'
        self.assertEqual(visitor.resolve('172.19.0.2',headers)['ip_source'],'peer')
        result=visitor.resolve('172.19.0.2',self.headers(token,'2001:4860:4860::8888'))
        self.assertEqual(result['ip_source'],'verified_proxy');self.assertEqual(result['client_ip'],'2001:4860:4860::8888')
    def test_local_country_database_and_stale_or_private_results(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'country.mmdb';path.write_bytes(b'synthetic fixture')
            class Reader:
                def metadata(self):return SimpleNamespace(build_epoch=1000)
                def get(self,address):return {'country':{'iso_code':'DE'}}
                def close(self):pass
            now=[2000];visitor=Visitors(database=str(path),clock=lambda:now[0],reader_factory=lambda _:Reader())
            self.assertEqual(visitor.resolve('8.8.8.8',self.headers())['country'],'DE')
            self.assertEqual(visitor.resolve('100.64.0.1',self.headers())['country_status'],'private_or_reserved')
            self.assertEqual(visitor.resolve('127.0.0.1',self.headers())['country'],None)
            now[0]+=91*86400
            self.assertEqual(visitor.resolve('8.8.8.8',self.headers())['country_status'],'database_outdated')
