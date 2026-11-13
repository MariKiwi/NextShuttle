"""Fail-closed ClamAV and native LMD adapters for a private Linux worker.

The deployment must isolate the worker/engines and make quarantine immutable to
untrusted users. These components do not decrypt or import Nextcloud files.
"""
from dataclasses import dataclass
import codecs
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time


class Blocked(Exception):
    def __init__(self, reason, engine=None):
        self.reason, self.engine = reason, engine
        super().__init__(reason)


@dataclass(frozen=True)
class Verdict:
    engine: str
    version: str
    signatures: str
    sha256: str


@dataclass(frozen=True)
class Approval:
    sha256: str
    bytes: int
    verdicts: tuple


def fingerprint(path, maximum=32*1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise Blocked("invalid_size_or_file")
        sha = hashlib.sha256()
        total = 0
        while chunk := file.read(65536):
            total += len(chunk)
            if total > maximum:
                raise Blocked("oversized_file")
            sha.update(chunk)
        end = os.fstat(file.fileno())
        if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (end.st_size, end.st_mtime_ns, end.st_ctime_ns) or total != metadata.st_size:
            raise Blocked("content_changed")
        return sha.hexdigest(), total


def run_bounded(command, timeout=60, max_output=65536):
    """No shell, bounded output and timeout, kill the subprocess group on failure."""
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"})
        except OSError:
            raise Blocked("scanner_unavailable")
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > max_output:
                    raise Blocked("scanner_timeout_or_output_limit")
                time.sleep(0.02)
            if os.fstat(output.fileno()).st_size > max_output:
                raise Blocked("scanner_output_limit")
            output.seek(0)
            return process.returncode, output.read(max_output).decode("utf-8", errors="strict")
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


class ClamAV:
    name = "clamav"
    def __init__(self, socket_path, *, timeout=30, max_age=48*3600, clock=time.time):
        self.socket_path, self.timeout, self.max_age, self.clock = str(socket_path), timeout, max_age, clock

    def connect(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.socket_path)
        except OSError:
            connection.close()
            raise Blocked("scanner_unavailable", self.name)
        return connection

    @staticmethod
    def response(connection):
        data = bytearray()
        while not data.endswith(b"\0"):
            chunk = connection.recv(1)
            if not chunk or len(data) >= 4096:
                raise Blocked("invalid_scanner_response", "clamav")
            data.extend(chunk)
        return bytes(data[:-1]).decode("ascii", errors="strict")

    def scan(self, path, expected_hash):
        try:
            with self.connect() as connection:
                connection.sendall(b"zVERSION\0")
                version = self.response(connection)
            match = re.fullmatch(r"ClamAV ([^/]+)/([0-9]+)/(.+)", version)
            if not match:
                raise Blocked("invalid_scanner_version", self.name)
            updated = datetime.strptime(match[3], "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
            if not -3600 <= self.clock()-updated <= self.max_age:
                raise Blocked("stale_signatures", self.name)
            with self.connect() as connection:
                connection.sendall(b"zINSTREAM\0")
                with open(path, "rb") as file:
                    total = 0
                    while chunk := file.read(65536):
                        total += len(chunk)
                        if total > 32*1024**2:
                            raise Blocked("oversized_file", self.name)
                        connection.sendall(struct.pack("!I", len(chunk)) + chunk)
                connection.sendall(b"\0\0\0\0")
                result = self.response(connection)
            if result.endswith(" FOUND"):
                if any(marker in result for marker in ('Heuristics.Limits.Exceeded','Heuristics.Encrypted','Heuristics.OLE2.ContainsMacros','Broken.Executable')):
                    raise Blocked('unsafe_or_uninspectable_content',self.name)
                raise Blocked("malware_detected", self.name)
            if result != "stream: OK":
                raise Blocked("scan_incomplete", self.name)
            return Verdict(self.name, match[1], match[2], expected_hash)
        except Blocked:
            raise
        except (OSError, ValueError, UnicodeError):
            raise Blocked("scanner_error", self.name)


class LMD:
    name = "lmd-native"
    def __init__(self, executable, signature_dir, *, timeout=60, max_age=48*3600,
                 clock=time.time, runner=run_bounded):
        self.executable, self.signatures = str(executable), Path(signature_dir)
        self.timeout, self.max_age, self.clock, self.runner = timeout, max_age, clock, runner
        if not os.path.isabs(self.executable):
            raise ValueError("Scanner executable must be an absolute path")

    def scan(self, path, expected_hash):
        from ingestion.signatures import verified
        try:
            with verified(self.signatures,self.max_age,self.clock):return self._scan(path,expected_hash)
        except Blocked:raise
        except (OSError,ValueError,TypeError,KeyError):raise Blocked('stale_or_missing_signatures',self.name)

    def _scan(self, path, expected_hash):
        # Each adapter call gets the exact scan ID, never a shared 'newest' report.
        started = int(self.clock())
        try:
            signature_version = (self.signatures / "maldet.sigs.ver").read_text().strip()
            options = "scan_user_access=1,scan_clamscan=0,scan_workers=1,scan_hashtype=both,scan_yara=0,scan_min_filesize=0,scan_max_filesize=32768k,scan_hexdepth=33554432,scan_ignore_root=0,scan_ignore_user=,scan_ignore_group=,quarantine_hits=0,quarantine_clean=0,quarantine_suspend_user=0,email_alert=0,slack_alert=0,telegram_alert=0,discord_alert=0,enable_statistic=0,autoupdate_signatures=0,autoupdate_version=0,post_scan_hook_exec="
            code, output = self.runner([self.executable, "--config-option", options, "--scan-all", str(path)], self.timeout)
            if code == 2:
                raise Blocked("malware_detected", self.name)
            if code != 0:
                raise Blocked("scan_incomplete", self.name)
            ids = re.findall(r"scan report saved, to view run: maldet --report ([0-9]{6}-[0-9]{4}\.[0-9]+)", output)
            if len(ids) != 1:
                raise Blocked("missing_scan_report", self.name)
            code, raw = self.runner([self.executable, "--json-report", ids[0]], self.timeout)
            if code != 0:
                raise Blocked("scan_incomplete", self.name)
            data = json.loads(raw)
            if data.get("schema_version") != "1.2" or len(data.get("reports", [])) != 1:
                raise Blocked("unsupported_scan_report", self.name)
            scanner, report = data["scanner"], data["reports"][0]
            if report.get("total_hits", 0) != 0:
                raise Blocked("malware_detected", self.name)
            if (scanner.get("engine") != "native" or scanner.get("version") != "2.0.1"
                or scanner.get("hash_type") != "both"
                or scanner.get("sig_version") != signature_version
                or report.get("scan_id") != ids[0] or report.get("path") != str(path)
                or type(report.get("total_files")) is not int or report["total_files"] != 1
                or type(report.get("total_hits")) is not int or report["total_hits"] != 0
                or report.get("total_cleaned") != 0 or report.get("total_quarantined") != 0
                or type(report.get("started_epoch")) is not int or report["started_epoch"] < started-1
                or type(report.get("completed_epoch")) is not int or report["completed_epoch"] < report["started_epoch"]
                or report["completed_epoch"] > self.clock()+60):
                raise Blocked("scan_incomplete_or_wrong_engine", self.name)
            return Verdict(self.name, scanner["version"], signature_version, expected_hash)
        except Blocked:
            raise
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            raise Blocked("scanner_error", self.name)


class ScanGate:
    def __init__(self, quarantine, clamav, lmd):
        self.quarantine = Path(quarantine).resolve(strict=True)
        if (clamav.name, lmd.name) != ("clamav", "lmd-native"):
            raise ValueError("Two independent scanner adapters are required")
        self.engines = clamav, lmd

    def check(self, path, original_name=None):
        original = Path(path)
        if original.is_symlink():
            raise Blocked("unsafe_path")
        path = original.resolve(strict=True)
        if not path.is_relative_to(self.quarantine):
            raise Blocked("unsafe_path")
        expected, size = fingerprint(path)
        from ingestion.content import Content
        inputs=Content(self.quarantine).inspect(path,original_name if original_name is not None else original.name)
        verdicts=[]
        deadline=time.monotonic()+110
        for index,(item,name) in enumerate(inputs):
            item_hash,item_size=fingerprint(item)
            for engine in self.engines:
                if time.monotonic()>deadline:raise Blocked('scan_budget_exceeded')
                verdict=engine.scan(item,item_hash)
                if verdict.engine!=engine.name or verdict.sha256!=item_hash or not verdict.version or not verdict.signatures:
                    raise Blocked('invalid_verdict',engine.name)
                if fingerprint(item)!=(item_hash,item_size):raise Blocked('content_changed',engine.name)
                if index==0:verdicts.append(verdict)
        if fingerprint(path)!=(expected,size):raise Blocked('content_changed')
        return Approval(expected,size,tuple(verdicts))
