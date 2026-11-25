from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from secrets import token_urlsafe
from tempfile import TemporaryDirectory
from time import time
from unittest import TestCase, skipUnless
from unittest.mock import patch
import json
import os
import sqlite3
import subprocess
import sys

from baseline_bridge import Baseline, frozen_catalog
from bootstrap_demo import render
from capability_registry import CapabilityRegistry
from plugins import host_catalog
from policy_engine import Denied, PolicyEngine, digest, wire
from server import CHANGE_TOOL, STATUS_TOOL, Server, parse


ROOT = Path(__file__).resolve().parent


class RuntimeTests(TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.tokens = {name: token_urlsafe(32).encode() for name in ("admin", "operator", "viewer")}
        self.raw = render(self.tokens, int(time()) + 3600)
        self.policy = self.load(self.raw)
        self.state = self.root / "state.sqlite"
        self.registry = self.registry_for(self.policy)
        self.registry.activate()

    def load(self, raw):
        path = self.root / "policy.toml"
        path.write_bytes(raw)
        return PolicyEngine(path, digest(raw))

    def registry_for(self, policy):
        return CapabilityRegistry(self.state, policy, host_catalog(),
                                  {*frozen_catalog(), STATUS_TOOL, CHANGE_TOOL})

    def session(self, name, policy=None):
        return (policy or self.policy).authenticate(name, self.tokens[name])

    def channel(self, name):
        session = self.session(name)
        return Server(self.registry, session, Baseline(self.policy, session, None))

    def enable(self):
        return self.registry.transition(self.session("admin"), "reports.preview", "enable", 0)

    def test_no_identity_or_role_spoof(self):
        with self.assertRaisesRegex(Denied, "AUTHENTICATION_DENIED"):
            self.policy.authenticate("admin", self.tokens["viewer"])
        with self.assertRaisesRegex(Denied, "CAPABILITY_DENIED"):
            self.channel("viewer").call(CHANGE_TOOL, {"tool": "reports.preview", "action": "enable",
                                                     "expected_generation": 0})
        self.enable()
        with self.assertRaisesRegex(Denied, "CAPABILITY_DENIED"):
            self.channel("viewer").call("reports.preview", {"text": "budget"})

    def test_enable_and_disable_cover_list_and_direct_call(self):
        operator = self.channel("operator")
        self.assertEqual(operator.list_tools()["tools"], [])
        self.enable()
        self.assertEqual([tool["name"] for tool in operator.list_tools()["tools"]], ["reports.preview"])
        result = operator.call("reports.preview", {"text": "Budget approved"})["structuredContent"]
        self.assertEqual(result["result"]["words"], 2)
        self.registry.transition(self.session("admin"), "reports.preview", "disable", 1)
        self.assertEqual(operator.list_tools()["tools"], [])
        with self.assertRaisesRegex(Denied, "CAPABILITY_DENIED"):
            operator.call("reports.preview", {"text": "Budget approved"})
        with closing(sqlite3.connect(self.state)) as db:
            rows = db.execute("SELECT previous,sha256,body FROM receipts ORDER BY sequence").fetchall()
        self.assertNotIn("Budget approved", str(rows))
        previous = "0" * 64
        for parent, claimed, body in rows:
            self.assertEqual(parent, previous)
            self.assertEqual(claimed, digest(bytes.fromhex(parent) + body.encode()))
            previous = claimed

    def test_deny_override_and_attribute_mismatch(self):
        for attributes in (b'tenant = "other", suspended = false', b'tenant = "analysis", suspended = true'):
            raw = self.raw.replace(b'tenant = "analysis", suspended = false', attributes, 1)
            policy = self.load(raw)
            self.assertFalse(policy.allows(self.session("operator", policy), "reports.preview", "invoke"))

    def test_management_is_separate_from_tool_use(self):
        admin = self.channel("admin")
        self.enable()
        self.assertEqual({tool["name"] for tool in admin.list_tools()["tools"]}, {STATUS_TOOL, CHANGE_TOOL})
        with self.assertRaisesRegex(Denied, "CAPABILITY_DENIED"):
            admin.call("reports.preview", {"text": "budget"})

    def test_policy_declared_capability_holds_until_host_binds_it(self):
        unbound = CapabilityRegistry(self.state, self.policy, (), {*frozen_catalog(), STATUS_TOOL, CHANGE_TOOL})
        admin = self.session("admin")
        with self.assertRaisesRegex(Denied, "CAPABILITY_NOT_READY"):
            unbound.transition(admin, "reports.preview", "enable", 0)
        self.assertEqual(unbound.status(admin, "reports.preview"),
                         {"tool": "reports.preview", "mode": "off", "generation": 0,
                          "installed": False, "pending": False})
        self.assertEqual(self.enable()["generation"], 1)

    def test_disable_drains_and_removed_tombstone_survives_restart(self):
        self.enable()
        lease = self.registry.admit(self.session("operator"), "reports.preview", {"text": "hello"}, plugin=True)
        admin = self.session("admin")
        with self.assertRaisesRegex(Denied, "CAPABILITY_NOT_SETTLED"):
            self.registry.transition(admin, "reports.preview", "remove", 1)
        self.registry.transition(admin, "reports.preview", "disable", 1)
        with self.assertRaisesRegex(Denied, "CAPABILITY_NOT_SETTLED"):
            self.registry_for(self.policy).transition(admin, "reports.preview", "remove", 2)
        self.registry.settle(lease, {"done": True}, status="PASS")
        self.registry_for(self.policy).transition(admin, "reports.preview", "remove", 2)
        with self.assertRaisesRegex(Denied, "CAPABILITY_REMOVED"):
            self.registry_for(self.policy).transition(admin, "reports.preview", "enable", 3)

    def test_stale_generation_and_policy_rollback(self):
        self.enable()
        with self.assertRaisesRegex(Denied, "GENERATION_CONFLICT"):
            self.registry.transition(self.session("admin"), "reports.preview", "disable", 0)
        newer = self.load(self.raw.replace(b"generation = 2", b"generation = 3"))
        replacement = self.registry_for(newer)
        replacement.activate()
        with self.assertRaisesRegex(Denied, "POLICY_STALE"):
            self.channel("operator").list_tools()
        self.assertEqual(replacement.status(self.session("admin", newer), "reports.preview")["mode"], "off")
        with self.assertRaisesRegex(Denied, "POLICY_ROLLBACK"):
            self.registry.activate()

    def test_concurrent_transitions_admit_one_writer(self):
        admin = self.session("admin")

        def enable():
            try:
                self.registry_for(self.policy).transition(admin, "reports.preview", "enable", 0)
                return "admitted"
            except Denied as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: enable(), range(2)))
        self.assertCountEqual(results, ["admitted", "GENERATION_CONFLICT"])

    def test_corrupt_mode_has_no_execution_authority(self):
        self.enable()
        with closing(sqlite3.connect(self.state)) as db, db:
            db.execute("UPDATE modes SET generation=55 WHERE name='reports.preview'")
        with self.assertRaisesRegex(Denied, "MODE_RECEIPT_INTEGRITY"):
            self.channel("operator").call("reports.preview", {"text": "budget"})

    def test_tampered_pin_and_expired_identity(self):
        with self.assertRaisesRegex(Denied, "POLICY_PIN_MISMATCH"):
            PolicyEngine(self.root / "policy.toml", "0" * 64)
        with patch("policy_engine.time", return_value=time() + 3601):
            with self.assertRaisesRegex(Denied, "AUTHENTICATION_DENIED"):
                self.session("admin")

    def test_json_and_baseline_hold(self):
        self.assertEqual(len(frozen_catalog()), 13)
        with self.assertRaisesRegex(Denied, "DUPLICATE_JSON_KEY"):
            parse(b'{"name":"a","name":"b"}')
        operator = self.channel("operator")
        self.assertEqual(operator.list_tools()["_meta"]["baselineStatus"], "HOLD")
        with self.assertRaisesRegex(Denied, "BASELINE_HOLD"):
            operator.call("list_files", {})

    def test_stdio_handshake_policy_reload_and_argument_validation(self):
        self.enable()
        token_file = self.root / "operator.token"
        token_file.write_bytes(self.tokens["operator"])
        frames = [
            {"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
            {"method": "notifications/initialized"},
            {"id": 2, "method": "tools/list"},
            {"id": 3, "method": "tools/call", "params": {
                "name": "reports.preview", "arguments": {"text": "hello", "role": "admin"}}},
            {"id": 4, "method": "tools/call", "params": {
                "name": "reports.preview", "arguments": {"text": "hello"}}},
        ]
        payload = b"".join(wire({"jsonrpc": "2.0", **frame}) + b"\n" for frame in frames)
        proc = subprocess.run([sys.executable, str(ROOT / "server.py"), "serve",
                               "--policy", str(self.root / "policy.toml"), "--policy-sha256", self.policy.sha256,
                               "--state", str(self.state), "--principal", "operator",
                               "--credential-file", str(token_file)], input=payload, capture_output=True, check=True)
        self.assertEqual(proc.stderr, b"")
        replies = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4])
        self.assertEqual(replies[1]["result"]["tools"][0]["name"], "reports.preview")
        self.assertTrue(replies[2]["result"]["isError"])
        self.assertFalse(replies[3]["result"]["isError"])

    @skipUnless(os.name == "posix" and os.getenv("HMT_TEST_SOVEREIGN") == "1", "requires POSIX sovereign kernel")
    def test_original_ports_recheck_sovereign_authority(self):
        witness = ROOT / "witness_baseline.py"
        process = {"enabled": True, "mode": "STDIN_JSON", "argv": [sys.executable, str(witness)],
                   "cwd": str(self.root), "timeout_ms": 3000, "max_output_bytes": 4096, "max_memory_mb": 128}
        key_env = "HMT_TEST_AUTHORITY_KEY"
        config = wire({
            "principal_id": "operator", "authority_hmac_env": key_env,
            "authority": process | {"pass_env": [key_env], "argv": [*process["argv"], "authority"]},
            "bindings": [{"binding_id": "fixture-list-files", "tool_names": ["list_files"],
                          "process": process | {"argv": [*process["argv"], "tool"]}}],
            "evidence_db": str(self.root / "baseline.sqlite"),
        })
        path = self.root / "baseline.json"
        path.write_bytes(config)
        raw = self.raw.replace(b"[principals.operator]\n",
                               f'[principals.operator]\nbaseline_config_sha256 = "{digest(config)}"\n'.encode())
        policy = self.load(raw.replace(b"generation = 2", b"generation = 3"))
        registry = self.registry_for(policy)
        registry.activate()
        session = self.session("operator", policy)
        channel = Server(registry, session, Baseline(policy, session, path))
        args = {"mission_packet": {"agent_authority_id": "lab", "decomposed_task_id": 0,
                                   "tasked_agent_id": "operator"}}
        with patch.dict(os.environ, {key_env: token_urlsafe(32)}):
            self.assertEqual(channel.list_tools()["tools"],
                             [{key: definition[key] for key in ("name", "description", "inputSchema")}
                              for definition in frozen_catalog().values()])
            self.assertFalse(channel.call("list_files", args)["isError"])
            (self.root / "revoked").touch()
            denied = channel.call("list_files", args)["structuredContent"]
            self.assertEqual(denied["status"], "DENY")
            self.assertEqual((self.root / "effects").read_text(), "1\n")
        with closing(sqlite3.connect(self.state)) as db:
            receipts = [json.loads(row[0]) for row in db.execute("SELECT body FROM receipts")]
        self.assertEqual(sum(row["kind"] == "sovereign_admitted" for row in receipts), 1)
