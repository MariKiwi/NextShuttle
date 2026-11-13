"""Separate update process; never sees user file quarantine or service secrets."""
import subprocess
import time
while True:
    for command in (["freshclam","--config-file=/etc/nextshuttle/freshclam.conf"],
                    ["/usr/local/maldetect/maldet","--update-sigs"]):
        try:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300)
            print('Signature update completed' if result.returncode==0 else 'Signature update failed',flush=True)
        except (OSError,subprocess.TimeoutExpired):print('Signature updater unavailable',flush=True)
    time.sleep(3600)
