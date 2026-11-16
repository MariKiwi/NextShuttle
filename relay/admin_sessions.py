"""Bounded, server-side admin sessions; restart invalidates every session."""
import hashlib
import secrets
import threading
from http.cookies import SimpleCookie,CookieError

class Sessions:
    cookie_name='__Host-nextshuttle_admin'
    def __init__(self,clock,capacity=512):self.clock=clock;self.capacity=capacity;self.rows={};self.lock=threading.Lock()
    def token(self,header):
        try:
            if header.count(self.cookie_name+'=')!=1:return ''
            cookie=SimpleCookie();cookie.load(header);value=cookie[self.cookie_name].value
            return value if len(value)==43 and all(c.isascii() and (c.isalnum() or c in '_-') for c in value) else ''
        except (CookieError,KeyError):return ''
    @staticmethod
    def key(token):return hashlib.sha256(token.encode()).hexdigest()
    def get(self,token):
        with self.lock:
            now=self.clock();self.rows={k:v for k,v in self.rows.items() if v['expires']>now and v['idle']>now}
            row=self.rows.get(self.key(token))
            if row is None:return None
            if row['authenticated']:row['idle']=min(row['expires'],now+1800)
            return dict(row)
    def create(self,authenticated=False,replace=''):
        with self.lock:
            now=self.clock();self.rows={k:v for k,v in self.rows.items() if v['expires']>now and v['idle']>now}
            if replace:self.rows.pop(self.key(replace),None)
            if len(self.rows)>=self.capacity:raise ValueError('Session capacity reached')
            token=secrets.token_urlsafe(32);ttl=28800 if authenticated else 300
            row={'authenticated':authenticated,'csrf':secrets.token_hex(32),'expires':now+ttl,'idle':now+(1800 if authenticated else ttl)}
            self.rows[self.key(token)]=row;return token,dict(row),ttl
    def remove(self,token):
        with self.lock:self.rows.pop(self.key(token),None)
