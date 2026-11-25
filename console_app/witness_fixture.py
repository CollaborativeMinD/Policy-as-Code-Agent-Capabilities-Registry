from contextlib import contextmanager
from secrets import token_urlsafe
from threading import Thread
import time

from baseline_bridge import frozen_catalog
from bootstrap_demo import render
from capability_registry import CapabilityRegistry
from http_transport import listener
from plugins import host_catalog
from policy_engine import PolicyEngine, digest
from server import STATUS_TOOL, CHANGE_TOOL

@contextmanager
def setup(tmp, root, config):
    tokens = {r: token_urlsafe(32).encode() for r in ("admin","viewer","operator")}
    raw = render(tokens, int(time.time()) + 600)
    path = tmp / "registry.toml"
    path.write_bytes(raw)
    policy = PolicyEngine(path, digest(raw))
    registry = CapabilityRegistry(tmp / "registry.sqlite", policy, host_catalog(),
                                  {*frozen_catalog(), STATUS_TOOL, CHANGE_TOOL})
    registry.activate()
    registry.transition(policy.authenticate("admin", tokens["admin"]), "reports.preview", "enable", 0)
    (tmp / "operator.token").write_bytes(tokens["operator"])
    with listener(registry, 0) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        upstream = tmp / "upstream.toml"
        upstream.write_text(f'port = {server.server_port}\ncredential_file = "operator.token"\n')
        try:
            yield config.replace(".local/registry-upstream.toml", upstream.as_posix())
        finally:
            server.shutdown()
            worker.join()


def check(effect):
    assert effect["status"] == "PASS" and effect["result"]["words"] == 3 and len(effect["receipt_sha256"]) == 64
