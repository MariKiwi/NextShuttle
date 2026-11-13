import base64
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import tempfile
import unittest

from relay.store import Rejected, Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.time = 10000
        self.store = Store(self.temp.name, capacity=1024, max_blob=512, clock=lambda: self.time)

    def tearDown(self):
        self.temp.cleanup()

    def download(self, body=b"opaque ciphertext", uses=1):
        obj = self.store.create_download({"bytes": len(body), "ttl": 60, "max_uses": uses})
        self.store.write("download", obj["id"], BytesIO(body), len(body))
        return obj

    def inbox(self):
        return self.store.create_inbox({"password": "a long inbox password", "ttl": 60,
            "public_key": base64.b64encode(b"k"*32).decode(), "max_bytes": 512, "max_files": 2})

    def reservation(self, inbox):
        return self.store.reserve_upload(inbox["id"], "a long inbox password", 16)

    def test_download_authorization_and_single_use(self):
        obj = self.download()
        with self.assertRaises(Rejected):
            self.store.fetch("download", obj["id"], "wrong")
        with self.store.fetch("download", obj["id"], obj["access_token"])[0] as file:
            self.assertEqual(file.read(), b"opaque ciphertext")
        with self.assertRaises(Rejected):
            self.store.fetch("download", obj["id"], obj["access_token"])

    def test_atomic_single_use_across_threads(self):
        obj = self.download()
        def attempt(_):
            try:
                with self.store.fetch("download", obj["id"], obj["access_token"])[0]:
                    return 1
            except Rejected:
                return 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)

    def test_expiry_denies_before_cleanup(self):
        obj = self.download()
        self.time += 60
        self.assertTrue(self.store.blob(obj["id"]).exists())
        with self.assertRaises(Rejected):
            self.store.fetch("download", obj["id"], obj["access_token"])

    def test_revoke_blocks_new_downloads(self):
        obj = self.download()
        self.store.revoke("download", obj["id"])
        with self.assertRaises(Rejected):
            self.store.fetch("download", obj["id"], obj["access_token"])
        self.store.cleanup()
        self.assertFalse(self.store.blob(obj["id"]).exists())

    def test_incomplete_blob_never_becomes_available(self):
        obj = self.store.create_download({"bytes": 20, "ttl": 60})
        with self.assertRaises(Rejected):
            self.store.write("download", obj["id"], BytesIO(b"short"), 20)
        with self.assertRaises(Rejected):
            self.store.fetch("download", obj["id"], obj["access_token"])
        self.assertFalse(self.store.blob(obj["id"]).exists())
        self.assertFalse(list(self.store.root.glob("*.part")))

    def test_wrong_length_and_overwrite_rejected(self):
        obj = self.store.create_download({"bytes": 20, "ttl": 60})
        with self.assertRaises(Rejected):
            self.store.write("download", obj["id"], BytesIO(b"x"), 1)
        self.store.write("download", obj["id"], BytesIO(b"x"*20), 20)
        with self.assertRaises(Rejected):
            self.store.write("download", obj["id"], BytesIO(b"y"*20), 20)

    def test_reservations_enforce_disk_capacity(self):
        self.store.create_download({"bytes": 512, "ttl": 60})
        self.store.create_download({"bytes": 512, "ttl": 60})
        with self.assertRaises(Rejected) as caught:
            self.store.create_download({"bytes": 1, "ttl": 60})
        self.assertEqual(caught.exception.status, 507)
        self.time += 60
        self.store.cleanup()
        self.store.create_download({"bytes": 512, "ttl": 60})

    def test_no_secrets_in_operational_list(self):
        obj = self.download()
        inbox = self.inbox()
        text = str(self.store.list())
        self.assertNotIn(obj["access_token"], text)
        self.assertNotIn("password", text)
        self.assertNotIn("public_key", text)
        self.assertIn(inbox["id"], text)

    def test_upload_password_and_quota(self):
        inbox = self.inbox()
        with self.assertRaises(Rejected):
            self.store.reserve_upload(inbox["id"], "wrong password here", 16)
        self.reservation(inbox)
        self.reservation(inbox)
        with self.assertRaises(Rejected) as caught:
            self.reservation(inbox)
        self.assertEqual(caught.exception.status, 413)

    def test_upload_one_time_write_and_import_receipt(self):
        obj = self.reservation(self.inbox())
        with self.assertRaises(Rejected):
            self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, "wrong")
        self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, obj["upload_token"])
        with self.assertRaises(Rejected):
            self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, obj["upload_token"])
        self.assertEqual(self.store.list(True)[0]["id"], obj["id"])
        with self.store.fetch("upload", obj["id"])[0] as file:
            self.assertEqual(file.read(), b"x"*16)
        self.store.revoke("upload", obj["id"])
        self.store.cleanup()
        self.assertEqual(self.store.list(True), [])

    def test_completed_upload_survives_inbox_expiry(self):
        inbox = self.inbox()
        obj = self.reservation(inbox)
        self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, obj["upload_token"])
        self.time += 61
        self.store.cleanup()
        self.assertEqual(len(self.store.list(True)), 1)
        self.time += self.store.retention
        self.store.cleanup()
        self.assertEqual(self.store.list(True), [])

    def test_expiry_rejects_unfinished_upload(self):
        obj = self.reservation(self.inbox())
        self.time += 60
        with self.assertRaises(Rejected):
            self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, obj["upload_token"])

    def test_password_rotation_invalidates_old_password_and_reservations(self):
        inbox = self.inbox()
        obj = self.reservation(inbox)
        self.store.rotate_password(inbox["id"], "a different long password")
        with self.assertRaises(Rejected):
            self.reservation(inbox)
        with self.assertRaises(Rejected):
            self.store.write("upload", obj["id"], BytesIO(b"x"*16), 16, obj["upload_token"])
        self.store.reserve_upload(inbox["id"], "a different long password", 16)

    def test_rate_limit_persists_across_instances(self):
        for _ in range(30):
            self.store.rate("source")
        other = Store(self.temp.name, clock=lambda: self.time)
        with self.assertRaises(Rejected) as caught:
            other.rate("source")
        self.assertEqual(caught.exception.status, 429)
        self.time += 61
        other.rate("source")

    def test_ids_and_limits_validated(self):
        for ident in ("../metadata.sqlite3", "x"*32, "0"*31, "0"*33):
            with self.assertRaises(Rejected):
                self.store.blob(ident)
        for size in (True, -1, 0, 513, "20"):
            with self.assertRaises(Rejected):
                self.store.create_download({"bytes": size, "ttl": 60})

    def test_explicit_ids_are_idempotent_without_reopening_a_download(self):
        data={'id':'a'*32,'access_token':'t'*43,'bytes':4,'expires':self.time+60,'max_uses':1}
        obj=self.store.create_download(data)
        self.assertEqual(self.store.create_download(data)['state'],'pending')
        self.store.write('download',obj['id'],BytesIO(b'data'),4)
        self.assertEqual(self.store.create_download(data)['state'],'ready')
        with self.assertRaises(Rejected):self.store.create_download({**data,'access_token':'x'*43})

    def test_separate_download_password_and_view_without_consumption(self):
        obj=self.store.create_download({'bytes':4,'ttl':60,'password':'separate strong password'})
        self.store.write('download',obj['id'],BytesIO(b'data'),4)
        view=self.store.view_download(obj['id'],obj['access_token'])
        self.assertTrue(view['available'] and view['requires_password'])
        for password in (None,'not the right password'):
            with self.assertRaises(Rejected):self.store.fetch('download',obj['id'],obj['access_token'],password)
        with self.store.fetch('download',obj['id'],obj['access_token'],'separate strong password')[0] as file:self.assertEqual(file.read(),b'data')
        self.assertFalse(self.store.view_download(obj['id'],obj['access_token'])['available'])

    def test_failed_download_can_be_reset_but_ready_download_cannot(self):
        obj=self.store.create_download({'bytes':4,'ttl':60})
        with self.assertRaises(Rejected):self.store.write('download',obj['id'],BytesIO(b'x'),4)
        self.store.reset_download(obj['id']);self.store.write('download',obj['id'],BytesIO(b'data'),4)
        with self.assertRaises(Rejected):self.store.reset_download(obj['id'])

    def test_public_rate_exhaustion_does_not_lock_out_private_service(self):
        for _ in range(30):
            self.store.rate("proxy", scope="public")
        with self.assertRaises(Rejected):
            self.store.rate("proxy", scope="public")
        self.store.rate("proxy", scope="private")


if __name__ == "__main__":
    unittest.main()
