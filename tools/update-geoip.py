#!/usr/bin/env python3
"""Download a public country MMDB; never sends visitor addresses to a service."""
import argparse
from datetime import datetime,timezone
import gzip
from pathlib import Path
import re
import tempfile
from urllib.request import Request,urlopen
import os

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--month',default=datetime.now(timezone.utc).strftime('%Y-%m'))
    parser.add_argument('--output',default='geoip/country.mmdb')
    args=parser.parse_args()
    if not re.fullmatch(r'20[0-9]{2}-(0[1-9]|1[0-2])',args.month):raise SystemExit('Expected YYYY-MM')
    destination=Path(args.output);destination.parent.mkdir(parents=True,exist_ok=True,mode=0o755);destination.parent.chmod(0o755)
    url='https://download.db-ip.com/free/dbip-country-lite-'+args.month+'.mmdb.gz'
    with tempfile.TemporaryFile() as compressed:
        total=0
        with urlopen(Request(url,headers={'User-Agent':'NextShuttle-country-database-updater'}),timeout=60) as response:
            while chunk:=response.read(65536):
                total+=len(chunk)
                if total>16*1024**2:raise RuntimeError('Compressed database exceeds budget')
                compressed.write(chunk)
        compressed.seek(0);name=None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as output:
                name=output.name;size=0
                with gzip.GzipFile(fileobj=compressed) as source:
                    while chunk:=source.read(65536):
                        size+=len(chunk)
                        if size>32*1024**2:raise RuntimeError('Database exceeds budget')
                        output.write(chunk)
                output.flush();os.fsync(output.fileno())
            with open(name,'rb') as source:
                source.seek(max(0,size-131072))
                if b'\xab\xcd\xefMaxMind.com' not in source.read():raise RuntimeError('Download is not an MMDB database')
            os.chmod(name,0o644);os.replace(name,destination);name=None
        finally:
            if name is not None:Path(name).unlink(missing_ok=True)
    print('Installed local country database for '+args.month+'. Attribution: https://db-ip.com (CC BY 4.0).')
if __name__=='__main__':main()
