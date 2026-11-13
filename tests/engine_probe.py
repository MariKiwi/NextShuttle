"""Independent real-engine EICAR checks, executed inside the private CI worker."""
import base64
import tempfile
from pathlib import Path
from ingestion.scanners import ClamAV,LMD,Blocked,fingerprint
sample=base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
with tempfile.TemporaryDirectory(dir='/quarantine') as work:
    path=Path(work)/'eicar.txt';path.write_bytes(sample);path.chmod(0o400)
    digest,_=fingerprint(path)
    for engine in (ClamAV('/run/nextshuttle/clamd.sock'),LMD('/usr/local/maldetect/maldet','/usr/local/maldetect/sigs')):
        try:engine.scan(path,digest)
        except Blocked as error:
            assert error.reason=='malware_detected',(engine.name,error.reason)
            print(engine.name+' independently rejected harmless EICAR')
        else:raise RuntimeError(engine.name+' did not reject EICAR')
