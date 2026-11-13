from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ingestion.scanners import Blocked, ClamAV, LMD, ScanGate, Verdict, fingerprint, run_bounded


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.file = self.root / "safe.txt"
        self.file.write_text("ordinary test text\n")
        self.sha, _ = fingerprint(self.file)
        self.now = int(time.time())
        self.sigs = self.root / "sigs"
        self.sigs.mkdir()
        for name in ("maldet.sigs.ver", "md5v2.dat", "hex.dat"):
            (self.sigs / name).write_text("20261113")
        self.report = {"schema_version": "1.2", "scanner": {"engine": "native", "version": "2.0.1", "sig_version": "20261113"},
            "reports": [{"scan_id": "261113-1200.1234", "path": str(self.file), "total_files": 1,
            "total_hits": 0, "total_cleaned": 0, "total_quarantined": 0, "started_epoch": self.now, "completed_epoch": self.now}]}

    def tearDown(self):
        self.temp.cleanup()

    def lmd(self, report=None, code=0):
        report = self.report if report is None else report
        def runner(command, timeout):
            if "--scan-all" in command:
                self.assertIn("scan_clamscan=0", command[2])
                return code, "scan report saved, to view run: maldet --report 261113-1200.1234\n"
            return 0, json.dumps(report)
        return LMD("/usr/local/maldetect/maldet", self.sigs, runner=runner, clock=lambda: self.now)

    def test_lmd_requires_native_completed_single_file_report(self):
        self.assertEqual(self.lmd().scan(self.file, self.sha).engine, "lmd-native")
        for key, value in (("total_files", 0), ("total_files", True), ("total_hits", 1),
                           ("total_cleaned", 1), ("path", "/some/other/file"), ("completed_epoch", None)):
            report = deepcopy(self.report)
            report["reports"][0][key] = value
            with self.assertRaises(Blocked):
                self.lmd(report).scan(self.file, self.sha)
        report = deepcopy(self.report)
        report["scanner"]["engine"] = "clamav"
        with self.assertRaises(Blocked):
            self.lmd(report).scan(self.file, self.sha)

    def test_lmd_error_detection_and_stale_signatures_fail_closed(self):
        for code in (1, 2, 77):
            with self.assertRaises(Blocked):
                self.lmd(code=code).scan(self.file, self.sha)
        os.utime(self.sigs / "hex.dat", (self.now-200000, self.now-200000))
        with self.assertRaises(Blocked):
            self.lmd().scan(self.file, self.sha)

    def test_clamd_responses_and_freshness_without_socket_permissions(self):
        class Connection:
            def __init__(inner, response): inner.response = bytearray(response+b"\0"); inner.sent = bytearray()
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
            def sendall(inner, data): inner.sent.extend(data)
            def recv(inner, count):
                data = inner.response[:count]; del inner.response[:count]; return bytes(data)
        date = datetime.fromtimestamp(self.now, timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
        adapter = ClamAV("/unused.sock", clock=lambda: self.now)
        for answer, clean in ((b"stream: OK", True), (b"stream: Test FOUND", False), (b"stream: size exceeded ERROR", False)):
            version = Connection(("ClamAV 1.4.3/12345/"+date).encode())
            scan = Connection(answer)
            with patch.object(adapter, "connect", side_effect=[version, scan]):
                if clean:
                    self.assertEqual(adapter.scan(self.file, self.sha).engine, "clamav")
                    self.assertTrue(scan.sent.startswith(b"zINSTREAM\0"))
                else:
                    with self.assertRaises(Blocked): adapter.scan(self.file, self.sha)
        with patch.object(adapter, "connect", return_value=Connection(b"ClamAV 1.4.3/12345/Mon Jan 01 00:00:00 2001")):
            with self.assertRaises(Blocked) as error: adapter.scan(self.file, self.sha)
            self.assertEqual(error.exception.reason, "stale_signatures")

    def test_clamd_unix_protocol_and_detection(self):
        path = self.root / "clam.sock"
        def serve(result):
            try:
                server = socket.socket(socket.AF_UNIX)
            except PermissionError:
                self.skipTest("This execution sandbox disallows UNIX sockets; CI runs this protocol test")
            server.bind(str(path)); server.listen()
            def read_until(connection, count):
                data = b""
                while len(data) < count:
                    data += connection.recv(count-len(data))
                return data
            def worker():
                try:
                    with server.accept()[0] as conn:
                        self.assertEqual(read_until(conn, 9), b"zVERSION\0")
                        date = datetime.fromtimestamp(self.now, timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
                        conn.sendall(("ClamAV 1.4.3/12345/"+date).encode()+b"\0")
                    with server.accept()[0] as conn:
                        self.assertEqual(read_until(conn, 10), b"zINSTREAM\0")
                        captured = b""
                        while True:
                            length = int.from_bytes(read_until(conn, 4), "big")
                            if not length: break
                            captured += read_until(conn, length)
                        self.assertEqual(captured, self.file.read_bytes())
                        conn.sendall(result+b"\0")
                finally:
                    server.close()
            thread = threading.Thread(target=worker)
            thread.start()
            return thread
        thread = serve(b"stream: OK")
        self.assertEqual(ClamAV(path, clock=lambda: self.now).scan(self.file, self.sha).signatures, "12345")
        thread.join(timeout=5); self.assertFalse(thread.is_alive())
        path.unlink()
        thread = serve(b"stream: Test-Signature FOUND")
        with self.assertRaises(Blocked) as error:
            ClamAV(path, clock=lambda: self.now).scan(self.file, self.sha)
        self.assertEqual(error.exception.reason, "malware_detected")
        thread.join(timeout=5); self.assertFalse(thread.is_alive())

    def test_gate_requires_both_verdicts_and_detects_mutation(self):
        class Engine:
            name = "clamav"
            def scan(inner, path, sha): return Verdict(inner.name, "test", "test", sha)
        self.assertEqual(len(ScanGate(self.root, Engine(), self.lmd()).check(self.file).verdicts), 2)
        class Mutator(Engine):
            def scan(inner, path, sha):
                path.write_text("changed")
                return super().scan(path, sha)
        with self.assertRaises(Blocked) as error:
            ScanGate(self.root, Mutator(), self.lmd()).check(self.file)
        self.assertEqual(error.exception.reason, "content_changed")

    def test_gate_rejects_unsafe_names_formats_binary_and_symlinks(self):
        class Never:
            name = "clamav"
            def scan(*args): raise AssertionError("Should fail before scanning")
        gate = ScanGate(self.root, Never(), self.lmd())
        for filename in ("../bad.txt", "bad.exe", "bad.zip", "bad\x00.txt", "bad\\test.txt"):
            with self.assertRaises(Blocked): gate.check(self.file, filename)
        self.file.write_bytes(b"\xff\x00binary")
        with self.assertRaises(Blocked): gate.check(self.file)
        link = self.root / "link.txt"; link.symlink_to(self.file)
        with self.assertRaises(Blocked): gate.check(link)

    def test_process_timeout_and_output_are_bounded(self):
        with self.assertRaises(Blocked):
            run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
        with self.assertRaises(Blocked):
            run_bounded([sys.executable, "-c", "print('x'*5000)"], max_output=1024)


if __name__ == "__main__":
    unittest.main()
