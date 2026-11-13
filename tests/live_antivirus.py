"""Real-engine staging probe. Uses only ordinary text and harmless EICAR."""
import base64
import json
import os
import time
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError

def request(data):
    r=Request(os.environ.get('NEXTSHUTTLE_PROBE_URL','http://127.0.0.1:8082/ingestion/v1/scan'),data=data,method='POST',headers={
        'Authorization':'Bearer '+('s'*64),'Content-Type':'application/octet-stream',
        'X-NextShuttle-Name':base64.b64encode(b'probe.txt').decode()})
    try:
        with urlopen(r,timeout=180) as response:return response.status,json.load(response)
    except HTTPError as e:return e.code,json.load(e)

ready=False
data={}
for attempt in range(60):
    try:
        code,data=request(b'ordinary live scanner probe\n')
        if code==200:
            assert sorted(v['engine'] for v in data['verdicts'])==['clamav','lmd-native']
            ready=True;break
    except (URLError,TimeoutError,ConnectionError) as error:data={'connection_error':str(error)}
    time.sleep(10)
if not ready:raise RuntimeError('Actual scanner/signature readiness did not pass: '+repr(data))
sample=base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
code,data=request(sample)
assert code==422 and data.get('reason')=='malware_detected',data
print('Actual ClamAV/native-LMD clean gate and EICAR rejection passed')
