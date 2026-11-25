"""Loopback-only JSON-response MCP transport. Authenticate each POST before dispatch."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import sqlite3

from baseline_bridge import Baseline
from policy_engine import Denied, wire
from server import MAX_FRAME, MAX_RESPONSE, Server, error, parse

VERSION = "2026-07-28"
PREFIX = "io.modelcontextprotocol/"


class Handler(BaseHTTPRequestHandler):
    timeout = 5

    def log_message(self, *args):
        pass  # Requests may contain credentials or private arguments.

    def reply(self, status, message):
        payload = wire(message)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        address = f"127.0.0.1:{self.server.server_port}"
        if self.path != "/mcp":
            return self.reply(404, error(None, -32600, "UNKNOWN_PATH"))
        if self.headers.get_all("Host") != [address] or self.headers.get_all("Origin") not in (
            None, ["http://" + address]
        ):
            return self.reply(403, error(None, -32600, "ORIGIN_DENIED"))
        auth = self.headers.get_all("Authorization", [])
        token = re.fullmatch(r"Bearer ([A-Za-z0-9._~-]{1,256})", auth[0]) if len(auth) == 1 else None
        try:
            if token is None:
                raise Denied("AUTHENTICATION_DENIED")
            registry = self.server.registry
            session = registry.policy.authenticate_bearer(token[1].encode("ascii"))
        except Denied:
            return self.reply(401, error(None, -32000, "AUTHENTICATION_DENIED"))
        sizes = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") is not None or len(sizes) != 1
                or not re.fullmatch(r"[0-9]{1,7}", sizes[0]) or int(sizes[0]) > MAX_FRAME):
            return self.reply(400, error(None, -32600, "FRAME_LIMIT"))
        if self.headers.get_content_type() != "application/json":
            return self.reply(415, error(None, -32600, "JSON_REQUIRED"))
        try:
            message = parse(self.rfile.read(int(sizes[0])))
        except (ValueError, TypeError, RecursionError):
            return self.reply(400, error(None, -32700, "INVALID_JSON"))
        if not isinstance(message, dict) or type(message.get("id")) not in (str, int):
            return self.reply(400, error(None, -32600, "INVALID_REQUEST"))
        identifier = message["id"]
        method = message.get("method")
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        if (not isinstance(method, str) or not isinstance(meta, dict)
                or not isinstance(meta.get(PREFIX + "protocolVersion"), str)
                or not isinstance(meta.get(PREFIX + "clientCapabilities"), dict)):
            return self.reply(400, error(identifier, -32602, "INVALID_ENVELOPE"))
        version = meta[PREFIX + "protocolVersion"]
        mirrored = {"Mcp-Protocol-Version": version, "Mcp-Method": method}
        if method in ("tools/call", "prompts/get", "resources/read"):
            mirrored["Mcp-Name"] = params.get("uri" if method == "resources/read" else "name")
        if (any(self.headers.get_all(key) != [value] for key, value in mirrored.items())
                or any(key.lower().startswith("mcp-param-") for key in self.headers)):
            return self.reply(400, error(identifier, -32020, "HEADER_MISMATCH"))
        if version != VERSION:
            response = error(identifier, -32022, "UNSUPPORTED_PROTOCOL_VERSION")
            response["error"]["data"] = {"requested": version, "supported": [VERSION]}
            return self.reply(400, response)
        try:
            registry.check(session)
            config = self.server.baseline_config if registry.policy.baseline_config_pin(session) else None
            baseline = Baseline(registry.policy, session, config)
            response = Server(registry, session, baseline, stateless=True).handle(message)
        except (ValueError, OSError, sqlite3.Error):
            return self.reply(403, error(identifier, -32000, "ADMISSION_UNAVAILABLE"))
        if "result" in response:
            result = response["result"]
            result["resultType"] = "complete"
            result.setdefault("_meta", {})[PREFIX + "serverInfo"] = {"name": "hmt-zero-trust-mcp", "version": "1.1.0"}
            if method.endswith("/list") or method == "server/discover":
                result.update(cacheScope="private", ttlMs=0)
        if len(wire(response)) > MAX_RESPONSE:
            response = error(identifier, -32000, "RESPONSE_LIMIT")
        code = response.get("error", {}).get("code")
        self.reply(404 if code == -32601 else 400 if code in (-32600, -32602) else 200, response)


def listener(registry, port, baseline_config=None):
    http = HTTPServer(("127.0.0.1", port), Handler)
    http.registry = registry
    http.baseline_config = baseline_config
    return http
