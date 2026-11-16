"""Trusted proxy attribution and local-only country lookups."""
import hmac
import ipaddress
from pathlib import Path
import re
import threading
import time

class Visitors:
    def __init__(self,proxies='',proxy_token='',database='',clock=time.time,reader_factory=None):
        self.proxies=[ipaddress.ip_network(value.strip()) for value in proxies.split(',') if value.strip()]
        self.token=proxy_token;self.database=Path(database) if database else None;self.clock=clock;self.reader=None;self.version=None;self.lock=threading.Lock();self.factory=reader_factory
        if proxy_token and not re.fullmatch(r'[A-Za-z0-9_-]{43,128}',proxy_token):raise ValueError('Invalid proxy verification token')
    def country(self,address):
        if not address.is_global:return None,'private_or_reserved'
        if self.database is None:return None,'database_missing'
        try:
            with self.lock:
                stat=self.database.stat()
                if stat.st_size>32*1024**2:raise ValueError()
                version=(stat.st_ino,stat.st_mtime_ns,stat.st_size)
                if self.version!=version:
                    if self.reader is not None:self.reader.close();self.reader=None
                    factory=self.factory
                    if factory is None:
                        import maxminddb
                        factory=maxminddb.open_database
                    self.reader=factory(str(self.database));self.version=version
                age=self.clock()-self.reader.metadata().build_epoch
                if not -86400<=age<=90*86400:return None,'database_outdated'
                record=self.reader.get(str(address)) or {};code=(record.get('country') or {}).get('iso_code')
                return (code,'local_database') if isinstance(code,str) and re.fullmatch('[A-Z]{2}',code) and code!='ZZ' else (None,'country_unknown')
        except (OSError,ValueError,TypeError,AttributeError,ImportError):return None,'database_unavailable'
    def resolve(self,peer,headers):
        address=ipaddress.ip_address(peer);source='peer'
        trusted=bool(self.token) and any(address in network for network in self.proxies)
        supplied=headers.get_all('X-NextShuttle-Proxy-Token',[])
        claimed=headers.get_all('X-NextShuttle-Client-IP',[])
        if trusted and len(supplied)==1 and len(claimed)==1 and hmac.compare_digest(supplied[0].encode(),self.token.encode()):
            try:address=ipaddress.ip_address(claimed[0]);source='verified_proxy'
            except ValueError:pass
        if address.version==6 and address.ipv4_mapped:address=address.ipv4_mapped
        country,status=self.country(address)
        return {'client_ip':str(address),'country':country,'ip_source':source,'country_status':status}
