"""Frozen baseline projection through the pinned kernel's sovereign ports."""

from pathlib import Path
import json
import os

from policy_engine import BASELINE_SHA256, digest, read_bounded, require
from registry_assets import asset


def frozen_catalog():
    raw = read_bounded(asset("baseline_catalog.json"), 262_144)
    require(digest(raw) == BASELINE_SHA256, "BASELINE_CATALOG_DRIFT")
    return {entry["name"]: entry for entry in json.loads(raw)["tools"]}


class Baseline:
    def __init__(self, policy, session, config_path: Path | None):
        self.catalog = frozen_catalog()
        self.ready = False
        expected = policy.baseline_config_pin(session)
        if config_path is None:
            return
        require(os.name == "posix", "SOVEREIGN_BINDING_REQUIRES_POSIX")
        raw = read_bounded(config_path, 262_144)
        require(expected is not None and digest(raw) == expected, "BASELINE_CONFIG_PIN_MISMATCH")

        from hmt_mcp_plus_server_kernel.adapter_registry import AdapterRegistry
        from hmt_mcp_plus_server_kernel.authority_client import AuthorityClient
        from hmt_mcp_plus_server_kernel.process_models import KernelConfig
        from hmt_mcp_plus_server_kernel.registry import Registry

        config = KernelConfig.model_validate_json(raw)
        require(config.principal_id == session.principal, "BASELINE_PRINCIPAL_MISMATCH")
        require(set(config.authority.pass_env) <= {config.authority_hmac_env}
                and all(not entry.process.pass_env for entry in config.bindings), "BASELINE_ENVIRONMENT_OVERREACH")
        registry = Registry.load()
        require({item.name: item.model_dump(mode="json", by_alias=True) for item in registry.catalog.tools}
                == self.catalog, "BASELINE_CATALOG_DRIFT")
        require(all(name in self.catalog for entry in config.bindings for name in entry.tool_names),
                "UNKNOWN_BASELINE_BINDING")
        self.registry = registry
        self.authority = AuthorityClient(config)
        self.adapters = AdapterRegistry(config)
        self.ready = True

    def list_tools(self, identifier):
        if not self.ready:
            return [], "HOLD"
        reply = self.authority.visibility(identifier)
        if not reply.authenticated or reply.decision != "ADMIT":
            return [], "DENY" if reply.authenticated and reply.decision == "DENY" else "HOLD"
        try:
            visible = self.registry.visible(reply.visible_tools)
        except ValueError:
            return [], "HOLD"
        return [definition.mcp_projection() for definition in visible], "PASS"

    def call(self, lease, name, args, record_admission):
        from hmt_mcp_plus_server_kernel.canonical import digest as upstream_digest
        from hmt_mcp_plus_server_kernel.schema_validation import SchemaViolation, validate_arguments

        definition = self.registry.get(name)
        try:
            validate_arguments(args, definition.input_schema)
        except SchemaViolation:
            return {"status": "DENY", "reason": "BASELINE_ARGUMENT_SCHEMA"}, True
        reply = self.authority.admit(lease, name, definition.schema_hash, upstream_digest(args), definition.effect)
        if not reply.authenticated or reply.decision != "ADMIT":
            status = "DENY" if reply.authenticated and reply.decision == "DENY" else "HOLD"
            return {"status": status, "reason": "BASELINE_SOVEREIGN_GATE"}, True
        record_admission(reply.reply_digest, reply.epoch_digest, definition.schema_hash)
        child = self.adapters.invoke(name, args)
        result = {"status": child.status}
        if child.status == "PASS":
            result["result"] = child.result
        return result, child.status == "PASS" or not child.started
