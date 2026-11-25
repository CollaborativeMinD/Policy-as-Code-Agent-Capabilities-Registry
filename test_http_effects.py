"""Exercise the stateless transport over a real loopback socket and inspect the effect ledger."""

from contextlib import closing
from http.client import HTTPConnection
import json
import sqlite3
from threading import Thread
from unittest import TestCase

from http_transport import PREFIX, VERSION, listener
import test_server


class HttpEffects(TestCase):
    setUp = test_server.RuntimeTests.setUp
    load = test_server.RuntimeTests.load
    registry_for = test_server.RuntimeTests.registry_for

    def test_pinned_frame_limit_reaches_http(self):
        candidate = self.raw.replace(b"frame_bytes = 1048576", b"frame_bytes = 512")
        self.assertNotEqual(candidate, self.raw)
        policy = self.load(candidate)
        with listener(self.registry_for(policy), 0) as http:
            thread = Thread(target=http.handle_request, daemon=True)
            thread.start()
            with closing(HTTPConnection("127.0.0.1", http.server_port, timeout=5)) as conn:
                headers = {"Authorization": "Bearer " + self.tokens["viewer"].decode(),
                           "Content-Type": "application/json"}
                conn.request("POST", "/mcp", b"x" * 513, headers)
                response = conn.getresponse()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response.read())["error"]["message"], "FRAME_LIMIT")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def test_kb_lifecycle_and_transport(self):
        http = listener(self.registry, 0)
        thread = Thread(target=http.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(http.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(http.shutdown)

        def post(role, method, params=None, override=None):
            params = dict(params or {})
            params["_meta"] = {PREFIX + "protocolVersion": VERSION, PREFIX + "clientCapabilities": {}}
            headers = {"Authorization": "Bearer " + self.tokens[role].decode(), "Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream", "Mcp-Method": method, "Mcp-Protocol-Version": VERSION}
            if "name" in params or "uri" in params:
                headers["Mcp-Name"] = params.get("name", params.get("uri"))
            headers.update(override or {})
            with closing(HTTPConnection("127.0.0.1", http.server_port, timeout=5)) as conn:
                conn.request("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}), headers)
                response = conn.getresponse()
                return response.status, json.loads(response.read())

        def change(name, action, generation):
            params = {"name": "capabilities.transition", "arguments": {"tool": name, "action": action,
                      "expected_generation": generation}}
            return post("admin", "tools/call", params)[1]["result"]["structuredContent"]

        def receipts():
            with closing(sqlite3.connect(self.state)) as db:
                return dict(db.execute("SELECT sha256,body FROM receipts"))

        self.assertEqual(post("operator", "server/discover")[1]["result"]["supportedVersions"], [VERSION])
        self.assertEqual(post("operator", "ping", override={"Authorization": "Bearer invalid"})[0], 401)
        self.assertEqual(post("operator", "ping", override={"Origin": "https://invalid.example"})[0], 403)
        self.assertEqual(post("operator", "ping", override={"Mcp-Method": "tools/list"})[0], 400)
        cases = (
            ("kb.search", "tools/call", {"name": "kb.search", "arguments": {"query": "rate limit", "limit": 1}},
             "tools", "api-rate-limit"),
            ("kb.catalog", "resources/read", {"uri": "kb://articles"}, "resources", "python-env"),
            ("kb.draft", "prompts/get", {"name": "draft_support_reply", "arguments": {"customer_message": "Help"}},
             "prompts", "Do not invent product policy"),
        )
        for name, method, params, surface, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(change(name, "enable", 0)["mode"], "on")
                self.assertTrue(post("operator", surface + "/list")[1]["result"][surface])
                self.assertFalse(post("viewer", surface + "/list")[1]["result"][surface])
                result = post("operator", method, params)[1]["result"]
                self.assertIn(expected, json.dumps(result))
                stamp = (result["structuredContent"] if method == "tools/call" else result["_meta"])["receipt_sha256"]
                self.assertEqual(json.loads(receipts()[stamp])["outcome"], "PASS")
                settled = json.loads(receipts()[stamp])
                admitted = json.loads(receipts()[settled["admission_sha256"]])
                self.assertEqual((admitted["principal"], admitted["tool"], admitted["policy_sha256"]),
                                 ("operator", name, self.policy.sha256))
                if name == "kb.search":
                    session = self.policy.authenticate("operator", self.tokens["operator"])
                    lease = self.registry.admit(session, name, {"query": "prior"}, plugin=True)
                    before = receipts()
                    held = post("operator", method, params)[1]["result"]["structuredContent"]
                    self.assertEqual(held, {"status": "HOLD", "reason": "CAPABILITY_BUSY_OR_UNSETTLED"})
                    self.assertEqual(before, receipts())
                    self.registry.settle(lease, {"fixture": "confirmed"}, status="PASS")
                before = receipts()
                denied = post("viewer", method, params)[1]
                self.assertIn("CAPABILITY_DENIED", json.dumps(denied))
                self.assertEqual(before, receipts())
                self.assertEqual(change(name, "disable", 1)["mode"], "off")
                before = receipts()
                self.assertIn("CAPABILITY_DENIED", json.dumps(post("operator", method, params)[1]))
                self.assertEqual(before, receipts())
                self.assertEqual(change(name, "remove", 2)["mode"], "removed")
                self.assertEqual(change(name, "enable", 3)["reason"], "CAPABILITY_REMOVED")
