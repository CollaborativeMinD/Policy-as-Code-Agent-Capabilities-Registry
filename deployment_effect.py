"""Compose release witness for cross-session authorization and sovereign admission."""

from hashlib import sha256
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent
POLICY_FIELDS = set()
RUNTIME_LOCK = "requirements.lock"
PRIMARY = "mcp"
WHEEL = "hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl"
WHEEL_SHA256 = "19f4e7e02c3f1b53aeb99d65bfbf8c076e2b20725fec5488e11313731d04a206"


def validate_policy(data):
    return None


def runtime_policy_sha256():
    from deploy_common import checksum
    return checksum(ROOT / "policy.example.toml")


def services(data, common):
    return {"services": {"mcp": common | {"network_mode": "none", "volumes": ["state:/state"]}},
            "volumes": {"state": {}}}


def exercise(call, policy_hash):
    from deploy_common import require

    def tool(name, arguments):
        return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}

    def change(action, generation):
        return tool("capabilities.transition", {"tool": "reports.preview", "action": action,
                                                "expected_generation": generation})

    before, = call("operator", [{"method": "tools/list"}])
    require(before["tools"] == [] and before["_meta"]["baselineStatus"] == "HOLD", "Default posture differs")
    rejected, = call("viewer", [change("enable", 0)])
    require(rejected["isError"], "Viewer changed capability state")
    enabled, = call("admin", [change("enable", 0)])
    require(enabled["structuredContent"]["mode"] == "on", "Admin failed to enable")
    result, = call("operator", [tool("reports.preview", {"text": "Quarterly report"})])
    require(result["structuredContent"]["result"]["words"] == 2, "Operator effect differs")
    disabled, removed = call("admin", [change("disable", 1), change("remove", 2)])
    denied, = call("operator", [tool("reports.preview", {"text": "Quarterly report"})])
    require(disabled["structuredContent"]["mode"] == "off"
            and removed["structuredContent"]["mode"] == "removed" and denied["isError"],
            "Removal did not block the cached call")
    reenable, = call("admin", [change("enable", 3)])
    require(reenable["structuredContent"]["reason"] == "CAPABILITY_REMOVED", "Tombstone did not persist")
    kb = {}
    for name, method, arguments, expected in (
        ("kb.search", "tools/call", {"name": "kb.search", "arguments": {"query": "rate limit"}}, "api-rate-limit"),
        ("kb.catalog", "resources/read", {"uri": "kb://articles"}, "python-env"),
        ("kb.draft", "prompts/get", {"name": "draft_support_reply", "arguments": {"customer_message": "Help"}},
         "Do not invent product policy"),
    ):
        transition = {"tool": name, "action": "enable", "expected_generation": 0}
        enabled_kb, = call("admin", [tool("capabilities.transition", transition)])
        require(enabled_kb["structuredContent"]["mode"] == "on", "KB enable failed")
        value, = call("operator", [{"method": method, "params": arguments}])
        require(expected in json.dumps(value), "KB effect differs")
        receipt = value["structuredContent"] if method == "tools/call" else value["_meta"]
        call("admin", [tool("capabilities.transition", transition | {"action": "disable", "expected_generation": 1})])
        blocked, = call("operator", [tool(name, arguments.get("arguments", {}))])
        require(blocked["structuredContent"]["status"] == "DENY", "Disabled KB effect escaped admission")
        kb[name] = {"allowed": "PASS", "receipt_sha256": receipt["receipt_sha256"], "after_disable": "DENY"}
    return {"kb": kb, "activated_policy_sha256": policy_hash, "enable": enabled["structuredContent"],
            "invocation": result["structuredContent"], "disable": disabled["structuredContent"],
            "remove": removed["structuredContent"], "reinvoke": denied["structuredContent"]}


def frames(messages):
    initial = [{"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
               {"method": "notifications/initialized"}]
    return "".join(json.dumps({"jsonrpc": "2.0", **frame}) + "\n"
                   for frame in initial + [{"id": index, **frame}
                                           for index, frame in enumerate(messages, 2)]).encode()


def replies(raw):
    return [json.loads(line)["result"] for line in raw.splitlines()[1:]]


def installed_smoke(scripts, cwd):
    from deploy_common import command
    suffix = ".exe" if os.name == "nt" else ""
    bootstrap = scripts / f"hmt-capability-bootstrap{suffix}"
    server = scripts / f"hmt-capability-server{suffix}"
    root = cwd / "installed"
    pin = command(str(bootstrap), str(root), cwd=cwd).decode().strip()
    options = ("--policy", str(root / "policy.toml"), "--policy-sha256", pin, "--state", str(root / "state.sqlite"))
    command(str(server), "activate", *options, cwd=cwd)

    def call(principal, messages):
        return replies(command(str(server), "serve", *options, "--principal", principal, "--credential-file",
                               str(root / f"{principal}.token"), input=frames(messages), cwd=cwd))

    return exercise(call, pin)


def build_options():
    from deploy_common import require
    wheel = Path(os.environ["HMT_SOVEREIGN_WHEEL_PATH"]) if os.getenv("HMT_SOVEREIGN_WHEEL_PATH") else (
        Path(os.environ.get("LOCALAPPDATA", ".")) / "ForgejoStation" / "inputs" / WHEEL)
    require(wheel.is_file() and sha256(wheel.read_bytes()).hexdigest() == WHEEL_SHA256,
            "Supply the pinned upstream kernel wheel to qualify the sovereign image")
    return ["--build-arg", f"SOVEREIGN_SHA256={WHEEL_SHA256}", "--secret", f"id=sovereign,src={wheel.resolve()}"]


def stack_env():
    return dict(os.environ)


def compose_smoke(stack, output):
    from deploy_common import command
    root = "/state/witness"
    pin = stack.run("mcp", root, entrypoint="hmt-capability-bootstrap").decode().strip()
    options = ("--policy", f"{root}/policy.toml", "--policy-sha256", pin, "--state", f"{root}/state.sqlite")
    stack.run("mcp", "activate", *options)

    def call(principal, messages):
        return replies(stack.run("mcp", "serve", *options, "--principal", principal,
                                 "--credential-file", f"{root}/{principal}.token", input=frames(messages)))

    observed = exercise(call, pin)
    container = stack.project + "-sovereign"
    stack("run", "-d", "-T", "--name", container, "--entrypoint", "sleep", "mcp", "180")
    try:
        command("docker", "exec", container, "mkdir", "/state/qualification")
        for filename in ("test_server.py", "witness_baseline.py", "baseline_catalog.json"):
            command("docker", "cp", str(ROOT / filename), f"{container}:/state/qualification/{filename}")
        command("docker", "exec", "-w", "/state/qualification", "-e", "HMT_TEST_SOVEREIGN=1", container,
                "python", "-B", "-W", "error", "-m", "unittest", "-v",
                "test_server.RuntimeTests.test_original_ports_recheck_sovereign_authority")
        observed["sovereign_fixture"] = "PASS"
    finally:
        command("docker", "rm", "-f", container)
    return observed
