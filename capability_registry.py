"""Shared capability state, effect admission, and durable lifecycle receipts."""

from contextlib import closing, contextmanager
from pathlib import Path
import json
import sqlite3
from time import time_ns
from uuid import uuid4

from policy_engine import Denied, digest, require, wire


class CapabilityRegistry:
    def __init__(self, path: Path, policy, bindings, reserved):
        self.path = path
        self.policy = policy
        self.bindings = {}
        for binding in bindings:
            require(binding.name not in reserved and binding.name not in self.bindings,
                    "BINDING_COLLISION")
            declared = policy.binding(binding.name)
            if declared is not None:
                require(declared == (binding.plugin, binding.sha256), "BINDING_PIN_MISMATCH")
                self.bindings[binding.name] = binding

    @staticmethod
    def _initialize(db):
        db.execute("""CREATE TABLE IF NOT EXISTS active (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                policy_id TEXT NOT NULL, generation INTEGER NOT NULL, sha256 TEXT NOT NULL
            ) STRICT""")
        db.execute("""CREATE TABLE IF NOT EXISTS modes (
                name TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK(mode IN ('on','off','removed')),
                generation INTEGER NOT NULL, policy_sha256 TEXT NOT NULL, receipt_sha256 TEXT NOT NULL
            ) STRICT""")
        db.execute("""CREATE TABLE IF NOT EXISTS pending (
                lease TEXT PRIMARY KEY, name TEXT NOT NULL, admission_sha256 TEXT NOT NULL
            ) STRICT""")
        db.execute("CREATE INDEX IF NOT EXISTS pending_name ON pending(name)")
        db.execute("""CREATE TABLE IF NOT EXISTS receipts (
                sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE,
                body TEXT NOT NULL
            ) STRICT""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS receipts_no_update BEFORE UPDATE ON receipts
                      BEGIN SELECT RAISE(ABORT, 'receipts are append only'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS receipts_no_delete BEFORE DELETE ON receipts
                      BEGIN SELECT RAISE(ABORT, 'receipts are append only'); END""")

    @contextmanager
    def tx(self, *, create=False):
        uri = self.path.resolve().as_uri() + ("?mode=rwc" if create else "?mode=rw")
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db, db:
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA synchronous = FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def activate(self):
        """Host deployment entry point. The launcher supplies an independently trusted pin."""
        with self.tx(create=True) as db:
            self._initialize(db)
            current = db.execute("SELECT policy_id,generation,sha256 FROM active").fetchone()
            incoming = self.policy.policy_id, self.policy.generation, self.policy.sha256
            if current == incoming:
                return
            require(current is None or (current[0] == incoming[0] and current[1] < incoming[1]),
                    "POLICY_ROLLBACK_OR_CONFLICT")
            db.execute("INSERT OR REPLACE INTO active VALUES (1,?,?,?)", incoming)
            self._receipt(db, "policy_activated", previous_policy_sha256=current[2] if current else None)

    def _current(self, db, session):
        require(db.execute("SELECT sha256 FROM active").fetchone() == (self.policy.sha256,), "POLICY_STALE")
        self.policy.principal(session)

    def check(self, session):
        with self.tx() as db:
            self._current(db, session)

    def _receipt(self, db, kind, **details):
        row = db.execute("SELECT sha256 FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = row[0] if row else "0" * 64
        body = wire({"kind": kind, "observed_at_ns": time_ns(), "policy_sha256": self.policy.sha256,
                     "policy_generation": self.policy.generation, **details})
        stamp = digest(bytes.fromhex(previous) + body)
        db.execute("INSERT INTO receipts(previous,sha256,body) VALUES (?,?,?)",
                   (previous, stamp, body.decode("utf-8")))
        return stamp

    def _mode(self, db, name):
        row = db.execute("""SELECT mode,generation,policy_sha256,receipt_sha256
                         FROM modes WHERE name=?""", (name,)).fetchone()
        if row is None:
            return "off", 0
        mode, generation, policy_hash, receipt = row
        evidence = db.execute("SELECT previous,body FROM receipts WHERE sha256=?", (receipt,)).fetchone()
        require(evidence is not None and digest(bytes.fromhex(evidence[0]) + evidence[1].encode()) == receipt,
                "MODE_RECEIPT_INTEGRITY")
        body = json.loads(evidence[1])
        require((body.get("kind"), body.get("tool"), body.get("mode"), body.get("generation"),
                 body.get("policy_sha256")) == ("mode_changed", name, mode, generation, policy_hash),
                "MODE_RECEIPT_INTEGRITY")
        return (mode if mode == "removed" or policy_hash == self.policy.sha256 else "off", generation)

    @staticmethod
    def _busy(db, name):
        return db.execute("SELECT 1 FROM pending WHERE name=? LIMIT 1", (name,)).fetchone() is not None

    def visible(self, session):
        with self.tx() as db:
            self._current(db, session)
            return [self.bindings[name].tool() for name in self.policy.tools()
                    if name in self.bindings and self._mode(db, name)[0] == "on"
                    and self.policy.allows(session, name, "list") and self.policy.allows(session, name, "invoke")]

    def has_access(self, session, actions):
        with self.tx() as db:
            self._current(db, session)
            return any(self.policy.allows(session, name, action)
                       for name in self.policy.tools() for action in actions)

    def status(self, session, name):
        with self.tx() as db:
            self._current(db, session)
            require(self.policy.allows(session, name, "status"), "CAPABILITY_DENIED")
            mode, generation = self._mode(db, name)
            return {"tool": name, "mode": mode, "generation": generation,
                    "installed": mode != "removed" and name in self.bindings, "pending": self._busy(db, name)}

    def transition(self, session, name, action, expected_generation):
        require(action in {"enable", "disable", "remove"}, "CAPABILITY_DENIED")
        with self.tx() as db:
            self._current(db, session)
            require(self.policy.allows(session, name, action), "CAPABILITY_DENIED")
            before, generation = self._mode(db, name)
            require(generation == expected_generation, "GENERATION_CONFLICT")
            require(before != "removed", "CAPABILITY_REMOVED")
            if action == "enable":
                require(name in self.bindings and not self._busy(db, name), "CAPABILITY_NOT_READY")
            if action == "remove":
                require(before == "off" and not self._busy(db, name), "CAPABILITY_NOT_SETTLED")
            mode = {"enable": "on", "disable": "off", "remove": "removed"}[action]
            generation += 1
            body = {"tool": name, "previous_mode": before, "mode": mode, "generation": generation}
            stamp = self._receipt(db, "mode_changed", principal=session.principal, action=action, **body)
            db.execute("INSERT OR REPLACE INTO modes VALUES (?,?,?,?,?)",
                       (name, mode, generation, self.policy.sha256, stamp))
            return body | {"receipt_sha256": stamp}

    def admit(self, session, name, args, *, plugin):
        with self.tx() as db:
            self._current(db, session)
            generation = None
            contract_sha256 = None
            if plugin:
                mode, generation = self._mode(db, name)
                require(mode == "on" and self.policy.allows(session, name, "invoke")
                        and name in self.bindings, "CAPABILITY_DENIED")
                contract_sha256 = self.bindings[name].sha256
            require(not self._busy(db, name), "CAPABILITY_BUSY_OR_UNSETTLED")
            lease = uuid4().hex
            stamp = self._receipt(db, "call_admitted", lease=lease, tool=name, principal=session.principal,
                                  generation=generation, contract_sha256=contract_sha256,
                                  payload_sha256=digest(wire(args)))
            db.execute("INSERT INTO pending VALUES (?,?,?)", (lease, name, stamp))
            return lease

    def settle(self, lease, result, *, status):
        with self.tx() as db:
            entry = db.execute("SELECT name,admission_sha256 FROM pending WHERE lease=?", (lease,)).fetchone()
            require(entry is not None, "LEASE_UNKNOWN")
            stamp = self._receipt(db, "call_settled", lease=lease, tool=entry[0], admission_sha256=entry[1],
                                  outcome=status, result_sha256=digest(wire(result)))
            db.execute("DELETE FROM pending WHERE lease=?", (lease,))
            return stamp

    def record_sovereign(self, session, lease, authority_sha256, epoch_sha256, schema_sha256):
        with self.tx() as db:
            self._current(db, session)
            entry = db.execute("SELECT name,admission_sha256 FROM pending WHERE lease=?", (lease,)).fetchone()
            require(entry is not None, "LEASE_UNKNOWN")
            return self._receipt(db, "sovereign_admitted", lease=lease, tool=entry[0], admission_sha256=entry[1],
                                 authority_sha256=authority_sha256, epoch_sha256=epoch_sha256,
                                 schema_sha256=schema_sha256)
