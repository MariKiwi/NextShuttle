"""Independent real-engine EICAR checks, executed inside the private CI worker."""
import base64
import tempfile
from pathlib import Path
from ingestion.scanners import ClamAV,LMD,Blocked,fingerprint,run_bounded
records=[]
def diagnostic_runner(command,timeout):
    code,output=run_bounded(command,timeout);records.append((code,output[-8192:]));return code,output
with tempfile.TemporaryDirectory(dir='/quarantine') as work:
    path=Path(work)/'ordinary.txt';path.write_bytes(b'ordinary independent scanner probe\n');path.chmod(0o400)
    digest,_=fingerprint(path)
    for engine in (ClamAV('/run/nextshuttle/clamd.sock'),LMD('/usr/local/maldetect/maldet','/usr/local/maldetect/sigs',runner=diagnostic_runner)):
        try:engine.scan(path,digest)
        except Blocked as error:
            print('Synthetic clean probe failed:',engine.name,error.reason,records,flush=True);raise
        print(engine.name+' independently cleared ordinary text',flush=True)
sample=base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
with tempfile.TemporaryDirectory(dir='/quarantine') as work:
    path=Path(work)/'eicar.txt';path.write_bytes(sample);path.chmod(0o400)
    digest,_=fingerprint(path)
    for engine in (ClamAV('/run/nextshuttle/clamd.sock'),LMD('/usr/local/maldetect/maldet','/usr/local/maldetect/sigs',runner=diagnostic_runner)):
        try:engine.scan(path,digest)
        except Blocked as error:
            if error.reason!='malware_detected':print('Synthetic LMD probe diagnostics:',records,flush=True)
            assert error.reason=='malware_detected',(engine.name,error.reason)
            print(engine.name+' independently rejected harmless EICAR')
        else:raise RuntimeError(engine.name+' did not reject EICAR')
