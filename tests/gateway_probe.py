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
