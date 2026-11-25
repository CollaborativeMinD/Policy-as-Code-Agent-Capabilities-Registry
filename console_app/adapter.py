"""Delegate to the registry's stateless HTTP transport and native capability lease."""
from contextlib import closing
from hashlib import sha256
from http.client import HTTPConnection
import json
import tomllib

TITLE = "Agent Capabilities Registry"
OPERATIONS = {"reports.preview", "kb.search"}


def validate(binding, inputs):
    if not isinstance(inputs, dict):
        raise ValueError("Expected a TOML input table")
    if binding["operation"] == "reports.preview":
        if set(inputs) != {"text"} or type(inputs["text"]) is not str or not 1 <= len(inputs["text"]) <= 4096:
            raise ValueError("Expected 1 to 4096 characters of report text")
    elif set(inputs) != {"query","limit"} or type(inputs["query"]) is not str or not 1 <= len(inputs["query"].strip()) <= 256 or type(inputs["limit"]) is not int or not 1 <= inputs["limit"] <= 3:
        raise ValueError("Invalid knowledge-base query or result limit")


def rpc(binding, method, params):
    source = binding["source"]
    raw = source.read_bytes()
    cfg = tomllib.loads(raw.decode())
    if set(cfg) != {"port","credential_file"} or type(cfg["port"]) is not int or not 1 <= cfg["port"] <= 65535:
        raise ValueError("Invalid registry upstream")
    token = (source.parent / cfg["credential_file"]).read_text().strip()
    version = "2026-07-28"
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json", "Mcp-Method": method,
               "Mcp-Protocol-Version": version, "Accept": "application/json, text/event-stream"}
    if "name" in params:
        headers["Mcp-Name"] = params["name"]
    meta = {"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientCapabilities": {}}
    message = {"jsonrpc":"2.0", "id":1, "method":method, "params":dict(params, _meta=meta)}
    with closing(HTTPConnection("127.0.0.1", cfg["port"], timeout=binding["runtime"].read_seconds)) as conn:
        conn.request("POST", "/mcp", json.dumps(message), headers)
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError("Native registry denied this credential or request")
        body = json.loads(response.read(262145))
    if "result" not in body or body["result"].get("isError"):
        raise ValueError("Native registry denied this operation")
    return raw, body["result"]


def observe(binding):
    raw, listing = rpc(binding, "tools/list", {})
    tool = next((t for t in listing["tools"] if t["name"] == binding["operation"]), None)
    if tool is None:
        raise ValueError("Capability unavailable under native policy")
    return sha256(raw + json.dumps(tool, sort_keys=True).encode()).hexdigest(), tool["name"] + " · available"


def execute(binding, inputs, directory, receipt_id, revision):
    if observe(binding)[0] != revision:
        raise ValueError("Registry scope changed")
    _, reply = rpc(binding, "tools/call", {"name": binding["operation"], "arguments": inputs})
    result = reply["structuredContent"]
    if result.get("status") != "PASS" or not result.get("receipt_sha256"):
        raise ValueError("Native capability did not return a settled receipt")
    return result
