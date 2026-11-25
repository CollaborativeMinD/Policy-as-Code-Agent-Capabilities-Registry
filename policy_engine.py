"""Strict, pinned TOML and local-session RBAC plus deny-overrides ABAC."""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from time import time
from typing import Annotated, Literal
import json
import re
import tomllib

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


Id = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Scalar = str | int | bool
Action = Literal["list", "invoke", "status", "enable", "disable", "remove"]
BASELINE_SHA256 = "3bcc9f860f6db8c6a6336cb50b282e369adcf95fabda0f923d5fd8fec2f2d653"


class Denied(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Denied(reason)


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        result = source.read(limit + 1)
    require(len(result) <= limit, "FILE_LIMIT")
    return result


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


class Principal(Contract):
    credential_sha256: Digest
    expires_at: Annotated[int, Field(gt=0)]
    roles: Annotated[list[Id], Field(min_length=1, max_length=16)]
    attributes: Annotated[dict[Id, Scalar], Field(max_length=32)]
    baseline_config_sha256: Digest | None = None


class Tool(Contract):
    plugin: Id
    contract_sha256: Digest
    attributes: Annotated[dict[Id, Scalar], Field(max_length=32)]


class Rule(Contract):
    effect: Literal["allow", "deny"]
    scopes: Annotated[list[str], Field(min_length=1, max_length=128)]
    match: Annotated[dict[str, Scalar], Field(min_length=1, max_length=32)]


class Declaration(Contract):
    version: Annotated[int, Field(ge=1, le=1)]
    policy_id: Id
    generation: Annotated[int, Field(ge=1, le=2**63 - 1)]
    baseline_catalog_sha256: Digest
    environment: Annotated[dict[Id, Scalar], Field(max_length=32)]
    principals: Annotated[dict[Id, Principal], Field(min_length=1, max_length=128)]
    roles: Annotated[dict[Id, list[str]], Field(min_length=1, max_length=64)]
    tools: Annotated[dict[Id, Tool], Field(max_length=64)]
    rules: Annotated[list[Rule], Field(max_length=256)]


@dataclass(frozen=True)
class Session:
    principal: str
    credential_sha256: str


class PolicyEngine:
    def __init__(self, path: Path, expected_sha256: str):
        raw = read_bounded(path, 131_072)
        self.sha256 = digest(raw)
        require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None
                and compare_digest(self.sha256, expected_sha256), "POLICY_PIN_MISMATCH")
        self._policy = Declaration.model_validate(tomllib.loads(raw.decode("utf-8")))
        self.generation = self._policy.generation
        self.policy_id = self._policy.policy_id
        require(self._policy.baseline_catalog_sha256 == BASELINE_SHA256, "BASELINE_PIN_MISMATCH")
        self._validate_references()

    def _validate_references(self):
        scopes = {f"{name}:{action}" for name in self._policy.tools
                  for action in ("list", "invoke", "status", "enable", "disable", "remove")}
        require(all(set(grants) <= scopes for grants in self._policy.roles.values()), "UNKNOWN_RBAC_SCOPE")
        credentials = [p.credential_sha256 for p in self._policy.principals.values()]
        require(len(set(credentials)) == len(credentials), "DUPLICATE_CREDENTIAL")
        for principal in self._policy.principals.values():
            require(set(principal.roles) <= self._policy.roles.keys(), "UNKNOWN_ROLE")
        attributes = {"principal": {key for p in self._policy.principals.values() for key in p.attributes},
                      "resource": {key for t in self._policy.tools.values() for key in t.attributes},
                      "environment": self._policy.environment.keys()}
        for rule in self._policy.rules:
            require(set(rule.scopes) <= scopes, "UNKNOWN_ABAC_SCOPE")
            for key in rule.match:
                namespace, _, attribute = key.partition(".")
                require(attribute in attributes.get(namespace, ()), "UNKNOWN_ABAC_ATTRIBUTE")

    def authenticate(self, principal_id: str, token: bytes) -> Session:
        require(32 <= len(token) <= 256, "AUTHENTICATION_DENIED")
        session = Session(principal_id, digest(token))
        self.principal(session)
        return session

    def principal(self, session: Session) -> Principal:
        principal = self._policy.principals.get(session.principal)
        require(principal is not None and principal.expires_at > time()
                and compare_digest(principal.credential_sha256, session.credential_sha256),
                "AUTHENTICATION_DENIED")
        return principal

    def baseline_config_pin(self, session: Session) -> str | None:
        return self.principal(session).baseline_config_sha256

    def tools(self):
        return tuple(sorted(self._policy.tools))

    def binding(self, name):
        tool = self._policy.tools.get(name)
        return (tool.plugin, tool.contract_sha256) if tool else None

    def allows(self, session: Session, name: str, action: Action) -> bool:
        principal = self.principal(session)
        tool = self._policy.tools.get(name)
        scope = f"{name}:{action}"
        if tool is None or not any(scope in self._policy.roles[role] for role in principal.roles):
            return False
        facts = {f"{namespace}.{key}": value
                 for namespace, group in (("principal", principal.attributes),
                                          ("resource", tool.attributes),
                                          ("environment", self._policy.environment))
                 for key, value in group.items()}
        effects = {rule.effect for rule in self._policy.rules if scope in rule.scopes
                   and all(type(facts.get(key)) is type(expected) and facts[key] == expected
                           for key, expected in rule.match.items())}
        return effects == {"allow"}
