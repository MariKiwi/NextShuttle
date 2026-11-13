"""Real session/CSRF/owner middleware checks on the disposable CI Nextcloud."""
import html
import http.cookiejar
import json
import re
import ssl
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import build_opener,HTTPCookieProcessor,HTTPSHandler,Request
from urllib.error import HTTPError
BASE='https://localhost:9083'
fixture=json.loads(Path('ci-state/http-fixture.json').read_text())
class Client:
    def __init__(self,user,password):
        self.opener=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()),HTTPSHandler(context=ssl.create_default_context(cafile='ci-state/ca.crt')))
        with self.opener.open(BASE+'/login') as r:page=r.read().decode()
        token=html.unescape(re.search(r'data-requesttoken="([^"]+)"',page).group(1))
        body=urlencode({'user':user,'password':password,'requesttoken':token}).encode()
        with self.opener.open(Request(BASE+'/login',data=body,headers={'Origin':BASE,'Referer':BASE+'/login'})) as r:
            page=r.read().decode()
            assert '/login' not in r.url,'Login did not establish a session for '+user
        self.token=html.unescape(re.search(r'data-requesttoken="([^"]+)"',page).group(1))
    def request(self,path,data=None,csrf=True):
        headers={'Accept':'application/json'}
        if csrf:headers['requesttoken']=self.token
        if data is not None:headers['Content-Type']='application/json'
        req=Request(BASE+'/index.php/apps/nextshuttle/'+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
        try:
            with self.opener.open(req) as r:return r.status,r.headers,r.read()
        except HTTPError as e:return e.code,e.headers,e.read()
alice=Client('alice','ephemeral-ci-password-246810')
bob=Client('bob','ephemeral-ci-password-246810')
admin=Client('admin','ephemeral-ci-admin-password-246810')
code,headers,body=alice.request('transfers');assert code==200,(code,body)
rows=json.loads(body)['transfers'];assert rows and any(x['id']==fixture['transfer'] for x in rows),rows
assert 'no-store' in headers.get('Cache-Control','')
code,_,body=bob.request('transfers');assert code==200 and json.loads(body)['transfers']==[],body
options={'kind':'download','nodeId':fixture['file'],'options':{'ttl':3600}}
code,_,body=alice.request('transfers',options,False);assert code in (401,403,412),(code,body)
code,_,body=bob.request('transfers',options);assert code in (403,404),(code,body)
code,_,body=bob.request('transfers/'+fixture['transfer']+'/revoke',{});assert code==404,(code,body)
code,_,body=alice.request('settings',{'policy':{}});assert code in (401,403),(code,body)
code,_,body=admin.request('settings',{'policy':{'require_download_password':True}});assert code==200,(code,body)
code,_,body=alice.request('transfers',options);assert code==400,(code,body)
options['options']['password']='a separate HTTP test password'
code,_,body=alice.request('transfers',options);assert code==200,(code,body)
print('Native session, owner, foreign node, CSRF, admin policy and no-store checks passed')
