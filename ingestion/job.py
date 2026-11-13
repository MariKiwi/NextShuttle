"""One disposable scan job with hard OS resource limits and structured output."""
import base64
from dataclasses import asdict
import json
from pathlib import Path
import resource
import sys
from ingestion.scanners import Blocked,ClamAV,LMD,ScanGate

def main():
    resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    resource.setrlimit(resource.RLIMIT_NPROC,(64,64))
    resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
    work,path,name=sys.argv[1:]
    try:
        gate=ScanGate(Path(work),ClamAV('/run/nextshuttle/clamd.sock'),LMD('/usr/local/maldetect/maldet','/usr/local/maldetect/sigs'))
        receipt=gate.check(Path(path),base64.b64decode(name,validate=True).decode())
        print(json.dumps(asdict(receipt)));return 0
    except Blocked as error:
        print(json.dumps({'reason':error.reason,'engine':error.engine}));return 2
    except Exception:
        print(json.dumps({'reason':'scanner_error'}));return 3
if __name__=='__main__':sys.exit(main())
