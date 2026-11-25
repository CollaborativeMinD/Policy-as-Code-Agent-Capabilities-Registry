"""Local stdio MCP server and trusted host policy activation entry point."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from typing import Literal
from uuid import uuid4

from pydantic import Field, ValidationError

from baseline_bridge import Baseline, frozen_catalog
from capability_registry import CapabilityRegistry
from plugins import host_catalog
from policy_engine import Contract, Denied, Id, PolicyEngine, read_bounded, require, wire


STATUS_TOOL = "capabilities.status"
CHANGE_TOOL = "capabilities.transition"
MAX_FRAME = 1_048_576
MAX_RESPONSE = 262_144
PROTOCOL_VERSION = "2025-11-25"


class Status(Contract):
    tool: Id


class Transition(Status):
    action: Literal["enable", "disable", "remove"]
    expected_generation: int = Field(ge=0, le=2**63 - 2)


def parse(line):
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    value = json.loads(line.decode("utf-8"), object_pairs_hook=pairs)
    wire(value)
    return value


def error(identifier, code, message):
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def tool_result(value, failed=False):
    return {"content": [{"type": "text", "text": wire(value).decode("utf-8")}],
            "structuredContent": value, "isError": failed}


class Server:
    def __init__(self, registry, session, baseline):
        self.registry = registry
        self.session = session
        self.baseline = baseline
        self.initialized = False
        self.ready = False

    def list_tools(self):
        tools = self.registry.visible(self.session)
        for name, description, arguments, actions in (
            (STATUS_TOOL, "Inspect a capability's current lifecycle state.", Status, ("status",)),
            (CHANGE_TOOL, "Enable, disable, or remove a capability.", Transition, ("enable", "disable", "remove")),
        ):
            if self.registry.has_access(self.session, actions):
                tools.append({"name": name, "description": description, "inputSchema": arguments.model_json_schema()})
        baseline, status = self.baseline.list_tools(uuid4().hex)
        self.registry.check(self.session)
        return {"tools": baseline + tools, "_meta": {"baselineStatus": status}}

    def call(self, name, arguments):
        self.registry.check(self.session)
        if name == STATUS_TOOL:
            args = Status.model_validate(arguments)
            return tool_result(self.registry.status(self.session, args.tool))
        if name == CHANGE_TOOL:
            args = Transition.model_validate(arguments)
            return tool_result(self.registry.transition(self.session, args.tool, args.action, args.expected_generation))
        if name in self.baseline.catalog:
            require(self.baseline.ready, "BASELINE_HOLD")
            lease = self.registry.admit(self.session, name, arguments, plugin=False)

            def record_admission(authority, epoch, schema):
                self.registry.record_sovereign(self.session, lease, authority, epoch, schema)

            result, settled = self.baseline.call(lease, name, arguments, record_admission)
            require(len(wire(result)) <= MAX_RESPONSE // 4, "OUTCOME_LIMIT")
            if settled:
                result["receipt_sha256"] = self.registry.settle(lease, result, status=result["status"])
            return tool_result(result, result["status"] != "PASS")

        binding = self.registry.bindings.get(name)
        require(binding is not None and self.registry.policy.allows(self.session, name, "invoke"), "CAPABILITY_DENIED")
        args = binding.arguments.model_validate(arguments)
        lease = self.registry.admit(self.session, name, arguments, plugin=True)
        try:
            result = binding.invoke(args)
            require(type(result) is dict and len(wire(result)) <= MAX_RESPONSE // 4, "OUTCOME_LIMIT")
        except Exception:
            raise Denied("CAPABILITY_OUTCOME_UNCERTAIN") from None
        stamp = self.registry.settle(lease, result, status="PASS")
        return tool_result({"status": "PASS", "result": result, "receipt_sha256": stamp})

    def handle(self, message):
        if type(message) is not dict or message.get("jsonrpc") != "2.0" or set(message) - {
            "jsonrpc", "method", "id", "params"
        }:
            return error(None, -32600, "INVALID_REQUEST")
        method, identifier = message.get("method"), message.get("id")
        if type(method) is not str or ("id" in message and type(identifier) not in (int, str)):
            return error(None, -32600, "INVALID_REQUEST")
        if "id" not in message:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            return None
        if type(identifier) is str and len(identifier) > 128:
            return error(None, -32600, "INVALID_REQUEST")
        params = message.get("params", {})
        if type(params) is not dict:
            return error(identifier, -32602, "INVALID_PARAMS")
        try:
            result = self.dispatch(method, params)
        except ValidationError:
            if method != "tools/call":
                return error(identifier, -32602, "ARGUMENT_SCHEMA")
            result = tool_result({"status": "DENY", "reason": "ARGUMENT_SCHEMA"}, True)
        except Denied as exc:
            if method != "tools/call":
                return error(identifier, -32000, str(exc))
            reason = str(exc)
            held = reason in {"BASELINE_HOLD", "CAPABILITY_OUTCOME_UNCERTAIN", "OUTCOME_LIMIT",
                              "CAPABILITY_BUSY_OR_UNSETTLED", "MODE_RECEIPT_INTEGRITY"}
            result = tool_result({"status": "HOLD" if held else "DENY", "reason": reason}, True)
        except (sqlite3.Error, OSError, RuntimeError):
            if method != "tools/call":
                return error(identifier, -32000, "EVIDENCE_OR_BINDING_UNAVAILABLE")
            result = tool_result({"status": "HOLD", "reason": "EVIDENCE_OR_BINDING_UNAVAILABLE"}, True)
        if result is None:
            return error(identifier, -32601, "METHOD_NOT_FOUND")
        return {"jsonrpc": "2.0", "id": identifier, "result": result}

    def dispatch(self, method, params):
        if method == "initialize":
            require(not self.initialized and type(params.get("protocolVersion")) is str, "INITIALIZATION_DENIED")
            self.registry.check(self.session)
            self.initialized = True
            return {"protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "hmt-zero-trust-mcp", "version": "1.0.0"}}
        require(self.ready, "NOT_INITIALIZED")
        if method == "ping":
            self.registry.check(self.session)
            return {}
        if method == "tools/list":
            require(not params.get("cursor"), "INVALID_CURSOR")
            return self.list_tools()
        if method == "tools/call":
            require(set(params) <= {"name", "arguments", "_meta"}, "INVALID_PARAMS")
            arguments = params.get("arguments", {})
            name = params.get("name")
            require(type(name) is str and len(name) <= 128 and type(arguments) is dict, "INVALID_PARAMS")
            return self.call(name, arguments)
        return None


def serve(server):
    for _ in range(10_000):
        line = sys.stdin.buffer.readline(MAX_FRAME + 1)
        if not line:
            return 0
        if len(line) > MAX_FRAME or not line.endswith(b"\n"):
            sys.stdout.buffer.write(wire(error(None, -32700, "FRAME_LIMIT")) + b"\n")
            return 3
        try:
            message = parse(line)
        except (ValueError, TypeError, RecursionError):
            response = error(None, -32700, "INVALID_JSON")
        else:
            response = server.handle(message)
        if response is not None:
            payload = wire(response)
            if len(payload) > MAX_RESPONSE:
                payload = wire(error(response["id"], -32000, "RESPONSE_LIMIT"))
            sys.stdout.buffer.write(payload + b"\n")
            sys.stdout.buffer.flush()
    return 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("activate", "serve"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--principal")
    parser.add_argument("--credential-file", type=Path)
    parser.add_argument("--baseline-config", type=Path)
    args = parser.parse_args()
    try:
        policy = PolicyEngine(args.policy, args.policy_sha256)
        registry = CapabilityRegistry(args.state, policy, host_catalog(),
                                      set(frozen_catalog()) | {STATUS_TOOL, CHANGE_TOOL})
        if args.operation == "activate":
            registry.activate()
            return 0
        require(args.principal is not None and args.credential_file is not None, "SESSION_REQUIRED")
        session = policy.authenticate(args.principal, read_bounded(args.credential_file, 256).strip())
        registry.check(session)
        return serve(Server(registry, session, Baseline(policy, session, args.baseline_config)))
    except (ValueError, OSError, ImportError, sqlite3.Error) as exc:
        print(f"STARTUP_HOLD:{type(exc).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
