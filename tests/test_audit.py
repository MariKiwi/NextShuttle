from io import BytesIO
from pathlib import Path
import re
import tempfile
import unittest

from relay.audit import KINDS
from relay.store import Store, Rejected


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_state_changes_and_claim_are_journaled(self):
        obj = self.store.create_download({"bytes": 4, "ttl": 60})
        self.store.write("download", obj["id"], BytesIO(b"data"), 4)
        with self.store.fetch("download", obj["id"], obj["access_token"])[0]:
            pass
        events = self.store.events()["events"]
        self.assertEqual([e["kind"] for e in events], ["download_created", "download_ready", "download_claimed"])
        self.assertNotIn(obj["access_token"], str(events))

    def test_replay_after_restart_and_ack_never_deletes(self):
        self.store.event("page_accessed")
        other = Store(self.temp.name)
        self.assertEqual(other.events()["events"][0]["kind"], "page_accessed")
        self.assertEqual(other.acknowledge(1), {"acknowledged": 1})
        self.assertEqual(len(other.events()["events"]), 1)
        self.assertEqual(other.events(1)["events"], [])
        self.assertEqual(other.acknowledge(0), {"acknowledged": 1})

    def test_no_free_text_or_secret_fields(self):
        for args in (("token=secret",), ("access_denied", "secret-token"), ("page_accessed", None, None, "untrusted")):
            with self.assertRaises(Rejected):
                self.store.event(*args)
        self.assertEqual(self.store.events()["events"], [])

    def test_cursor_gaps_and_invalid_limits_rejected(self):
        self.store.event("page_accessed")
        for after, limit in ((2, 10), (-1, 10), (0, 101), (True, 10)):
            with self.assertRaises(Rejected):
                self.store.events(after, limit)
        with self.assertRaises(Rejected):
            self.store.acknowledge(2)

    def test_transaction_rollback_does_not_claim_an_event(self):
        with self.assertRaises(RuntimeError):
            with self.store.tx() as db:
                self.store.event("page_accessed", db=db)
                raise RuntimeError()
        self.assertEqual(self.store.event("page_accessed"), 1)

    def test_relay_catalog_matches_nextcloud_notifier(self):
        source = (Path(__file__).parents[1] / "nextcloud/nextshuttle/lib/Service/EventCatalog.php").read_text()
        labels = set(re.findall(r"'([a-z_]+)' => '", source))
        self.assertEqual(KINDS, labels)

    def test_full_journal_blocks_state_changes_instead_of_dropping_events(self):
        with self.store.tx() as db:
            db.executemany("INSERT INTO audit_events(occurred,kind,severity) VALUES (1,'page_accessed','info')", [()] * 100000)
        with self.assertRaises(Rejected) as error:
            self.store.create_download({"bytes": 4, "ttl": 60})
        self.assertEqual(error.exception.status, 507)
        self.assertEqual(self.store.list()["downloads"], [])


if __name__ == "__main__":
    unittest.main()
