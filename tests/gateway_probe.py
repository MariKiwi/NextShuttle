"""CI-only gateway access check from an unrelated proxy network."""
from urllib.request import Request,urlopen
from urllib.error import HTTPError
for port,path,expected in [(9080,'/nextshuttle/',200),(9081,'/',200),(9082,'/ingestion/v1/health',200)]:
    headers={'Authorization':'Bearer '+('s'*64)} if port==9082 else {}
    request=Request('http://shuttle-gateway:'+str(port)+path,headers=headers)
    try:
        with urlopen(request,timeout=10) as response:status=response.status
    except HTTPError as error:status=error.code
    assert status==expected,(port,status)
    print('Gateway access passed on port',port,flush=True)
import base64
import json
for data,expected in [(b'ordinary gateway scan\n',200),(base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='),422)]:
    req=Request('http://shuttle-gateway:9082/ingestion/v1/scan',data=data,headers={
        'Authorization':'Bearer '+('s'*64),'Content-Type':'application/octet-stream','X-NextShuttle-Name':base64.b64encode(b'gateway.txt').decode()})
    try:
        with urlopen(req,timeout=180) as response:status=response.status;result=json.load(response)
    except HTTPError as error:status=error.code;result=json.load(error)
    assert status==expected,(status,result)
    if status==200:assert sorted(v['engine'] for v in result['verdicts'])==['clamav','lmd-native']
    else:assert result['reason']=='malware_detected',result
    print('Gateway scan verdict passed:',status,flush=True)
