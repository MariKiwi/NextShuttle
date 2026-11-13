from io import BytesIO
import http.client
import json
import tempfile
import threading
import unittest

from relay.server import BoundedServer, handler
from relay.store import Store


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.token = "t"*64
        self.servers = {}
        self.threads = []
        for mode in ("public", "private"):
            server = BoundedServer(("127.0.0.1", 0), handler(self.store, mode, self.token,
                "https://helios-public.tail43e437.ts.net/nextshuttle/"))
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            self.servers[mode] = server
            self.threads.append(thread)

    def tearDown(self):
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        self.temp.cleanup()

    def request(self, mode, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.servers[mode].server_address, timeout=5)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return result

    def test_private_requires_service_token(self):
        self.assertEqual(self.request("private", "GET", "/api/v1/transfers")[0], 401)
        self.assertEqual(self.request("private", "GET", "/api/v1/transfers", headers={"Authorization": "Bearer " + self.token})[0], 200)

    def test_management_routes_absent_on_public_listener(self):
        for path in ("/api/v1/transfers", "/nextshuttle/api/v1/transfers", "/nextshuttle/api/v1/cleanup"):
            self.assertEqual(self.request("public", "GET", path, headers={"Authorization": "Bearer " + self.token})[0], 404)

    def test_base_path_and_header_credentials(self):
        obj = self.store.create_download({"bytes": 6, "ttl": 60})
        self.store.write("download", obj["id"], BytesIO(b"cipher"), 6)
        path = "/nextshuttle/api/v1/downloads/" + obj["id"] + "/fetch"
        self.assertEqual(self.request("public", "POST", path + "?token=" + obj["access_token"], b"")[0], 404)
        status, body, headers = self.request("public", "POST", path, b"", {"Authorization": "Bearer " + obj["access_token"]})
        self.assertEqual((status, body), (200, b"cipher"))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_cross_origin_and_ambient_browser_management_denied(self):
        status = self.request("public", "POST", "/nextshuttle/api/v1/inboxes/" + "0"*32 + "/uploads", b"{}",
                              {"Origin": "https://evil.example", "Content-Type": "application/json"})[0]
        self.assertEqual(status, 403)
        self.assertEqual(self.request("private", "GET", "/api/v1/transfers", headers={
            "Authorization": "Bearer " + self.token, "Origin": "https://shuttle.helios.lan"})[0], 403)

    def test_body_and_type_limits(self):
        path = "/api/v1/downloads"
        auth = {"Authorization": "Bearer " + self.token}
        self.assertEqual(self.request("private", "POST", path, b"{}", auth)[0], 415)
        auth["Content-Type"] = "application/json"
        self.assertEqual(self.request("private", "POST", path, b"[]", auth)[0], 400)
        self.assertEqual(self.request("private", "POST", path, b" "*8193, auth)[0], 413)
        status, body, _ = self.request("private", "POST", path, json.dumps({"bytes": 10, "ttl": 60}), auth)
        self.assertEqual(status, 201)
        self.assertIn("access_token", json.loads(body))

    def test_page_and_wrong_codes_are_logged_without_credentials(self):
        self.assertEqual(self.request("public", "GET", "/nextshuttle/?password=must-not-log")[0], 200)
        obj = self.store.create_download({"bytes": 6, "ttl": 60})
        self.store.write("download", obj["id"], BytesIO(b"cipher"), 6)
        self.assertEqual(self.request("public", "POST", "/nextshuttle/api/v1/downloads/" + obj["id"] + "/fetch", b"", {"Authorization": "Bearer wrong-secret"})[0], 404)
        events = self.store.events()["events"]
        self.assertEqual(events[0]["kind"], "page_accessed")
        self.assertEqual(events[-1]["kind"], "wrong_code")
        self.assertEqual(events[-1]["object_id"], obj["id"])
        self.assertNotIn("must-not-log", str(events))
        self.assertNotIn("wrong-secret", str(events))

    def test_event_feed_private_and_poll_does_not_create_feedback_loop(self):
        self.store.event("page_accessed")
        auth = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        for _ in range(2):
            status, body, _ = self.request("private", "POST", "/api/v1/events/read", b'{"after":0}', auth)
            self.assertEqual(status, 200)
            self.assertEqual(len(json.loads(body)["events"]), 1)
        self.assertEqual(self.request("private", "POST", "/api/v1/events/ack", b'{"through":1}', auth)[0], 200)
        self.assertEqual(self.store.events()["acknowledged"], 1)
        self.assertEqual(self.request("public", "POST", "/nextshuttle/api/v1/events/read", b'{"after":0}', auth)[0], 404)


if __name__ == "__main__":
    unittest.main()
