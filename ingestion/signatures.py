"""Serialize native definition updates and verify a complete last-checked set."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time

REQUIRED=('maldet.sigs.ver','md5v2.dat','sha256v2.dat','hex.dat')
LOCK='.nextshuttle.lock'
RECEIPT='.nextshuttle-verified.json'

def inventory(root):
    root=Path(root);files={};total=0
    for path in sorted(root.iterdir()):
        if path.name.startswith('.nextshuttle') or path.is_dir():continue
        if path.is_symlink() or not path.is_file():raise ValueError('Invalid signature entry')
        total+=path.stat().st_size
        if total>256*1024**2 or len(files)>=100:raise ValueError('Signature budget exceeded')
        with path.open('rb') as source:
            digest=hashlib.sha256()
            while chunk:=source.read(65536):digest.update(chunk)
        files[path.name]=digest.hexdigest()
    if any(name not in files or not (root/name).stat().st_size for name in REQUIRED):raise ValueError('Missing definitions')
    return files

def record_verified(root,clock=time.time):
    """Caller holds exclusive lock after a successful upstream update check."""
    root=Path(root)
    record={'checked':int(clock()),'files':inventory(root)}
    tmp=root/(RECEIPT+'.tmp')
    with tmp.open('w') as out:json.dump(record,out);out.flush();os.fsync(out.fileno())
    tmp.chmod(0o644);os.replace(tmp,root/RECEIPT)

@contextmanager
def verified(root,max_age=48*3600,clock=time.time):
    root=Path(root)
    with (root/LOCK).open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        try:
            with (root/RECEIPT).open('rb') as source:raw=source.read(16385)
            if len(raw)>16384:raise ValueError('Invalid definition receipt')
            record=json.loads(raw)
            if type(record.get('checked')) is not int or not -3600<=clock()-record['checked']<=max_age:raise ValueError('Stale definitions')
            if record['files']!=inventory(root):raise ValueError('Incomplete definition update')
            yield int(clock()-record['checked'])
        finally:fcntl.flock(lock,fcntl.LOCK_UN)
