"""Separate signature updates, without user quarantine or service credentials."""
from pathlib import Path
import time
import fcntl
from contextlib import nullcontext
from ingestion.signatures import LOCK,record_verified
from ingestion.scanners import run_bounded,Blocked

def main():
    state=Path('/usr/local/maldetect/pub/shuttle')
    for folder in ('tmp','sess','quar'):(state/folder).mkdir(parents=True,exist_ok=True,mode=0o700)
    commands=[['freshclam','--config-file=/etc/nextshuttle/freshclam.conf','--quiet'],['/usr/local/maldetect/maldet','--update-sigs']]
    due=[0,0];failures=[0,0]
    while True:
        for index,command in enumerate(commands):
            if time.monotonic()<due[index]:continue
            try:
                definitions=Path('/usr/local/maldetect/sigs')
                with (definitions/LOCK).open('a+b') if index==1 else nullcontext() as lock:
                    if lock is not None:fcntl.flock(lock,fcntl.LOCK_EX)
                    code,output=run_bounded(command,timeout=300,max_output=65536)
                    if code==0 and index==1:record_verified(definitions)
                if code!=0:
                    print('Signature update failed: '+output[-4096:],flush=True)
                    failures[index]+=1
                else:
                    print('Signature update completed',flush=True);failures[index]=0
            except (OSError,ValueError) as error:
                print('Definition verification unavailable; scanning remains blocked',flush=True);failures[index]+=1
            except Blocked as error:
                print('Signature updater unavailable: '+error.reason,flush=True);failures[index]+=1
            delay=3600 if failures[index]==0 else min(3600,60*2**min(failures[index]-1,6))
            due[index]=time.monotonic()+delay
        time.sleep(30)
if __name__=='__main__':main()
