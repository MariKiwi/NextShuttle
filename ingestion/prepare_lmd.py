"""Small pinned-source compatibility patch for read-only signature mounts.

Native LMD chmods shared signature/log directories even in non-root scan mode.
Those metadata changes are unnecessary on deliberately read-only mounts, and
their stderr would contaminate machine-readable reports. Scan code is unchanged.
"""
from pathlib import Path
path=Path('/usr/local/maldetect/internals/lmd_init.sh')
source=path.read_text()
old='chmod 750 "$_dir"'
if source.count(old)!=1:raise SystemExit('Pinned LMD source no longer matches the reviewed compatibility patch')
path.write_text(source.replace(old,'if [ -w "$_dir" ]; then chmod 750 "$_dir"; fi'))
