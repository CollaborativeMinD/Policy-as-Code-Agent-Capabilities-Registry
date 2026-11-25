# Policy-as-Code Agent Capabilities Registry

A local stdio MCP server with a frozen 13-tool HMT baseline and a separate registry for host-installed plug-ins. The baseline uses the supplied kernel’s sovereign authority and tool adapters. Each plug-in tool requires an explicit RBAC grant and a matching ABAC allow. A matching ABAC deny overrides the grant.

## Change the system through policy

1. **Edit TOML first.** Declare the capability, who can use it, and the conditions for use. Bump the policy generation.
2. **Run admission.** Apply the candidate in a test state. Observe the expected allow or denial.
3. **Add code only for a missing behavior.** Declare the contract in policy and run it before adding the handler. Use the failure to locate the missing model, binding, or enforcement rule. Build that piece and run the same case again.
4. **Reconcile and stop.** Compare the effect and receipt with the policy. Verify an allowed case and a denied case. Once both match, leave the rest of the runtime alone.

Push the reviewed change through [qualification](.github/workflows/qualify.yml). A passing run qualifies the commit for promotion. The host operator activates the approved TOML by digest. [Runbook](Runbook.md) · [Agent guide](AGENTS.md) · [Capability policy skill](SKILL.md)

## Run the local demonstration

Use CPython 3.12 or 3.13 with SQLite 3.37 or later. Install the locked dependencies in a virtual environment. The demo creates three distinct credentials in a new private directory and prints the policy SHA-256. Credentials expire after one hour.

```powershell
python -m pip install -r requirements.lock
$policyHash = python bootstrap_demo.py local-demo
python server.py activate --policy local-demo/policy.toml --policy-sha256 $policyHash --state local-demo/state.sqlite
python server.py serve --policy local-demo/policy.toml --policy-sha256 $policyHash --state local-demo/state.sqlite --principal admin --credential-file local-demo/admin.token
```

The last command starts MCP stdio with the `2025-11-25` handshake. Use it as the MCP client’s launch command with absolute paths. Launch an operator session with the operator credential against the same state file. The default demo has no sovereign adapters configured. The baseline is registered and its catalog is verified, while baseline discovery reports `HOLD`.

| Identity | Demo permissions |
| --- | --- |
| Admin | Inspect and change `reports.preview` lifecycle state. |
| Operator | Discover and invoke `reports.preview` once enabled. |
| Viewer | Open an authenticated session with no extra capability grants. |

An admin calls `capabilities.status` with `{"tool":"reports.preview"}` to read the current generation, then calls `capabilities.transition` with `{"tool":"reports.preview","action":"enable","expected_generation":0}`. The operator can then call `reports.preview` with `{"text":"Quarterly report"}`. Use the latest returned generation for `disable` or `remove`. Relist after a change. Every execution rechecks current authorization even when the client has cached a tool name.

## Policy and lifecycle

| Component | Responsibility |
| --- | --- |
| [policy.example.toml](policy.example.toml) | Defines principals, credential fingerprints, roles, scoped RBAC grants, ABAC rules, and plug-in contract pins. |
| [plugins.py](plugins.py) | Registers reviewed host implementations with strict argument schemas. Deploy code through the host’s normal release path. |
| [capability_registry.py](capability_registry.py) | Commits lifecycle and invocation receipts, verifies mode receipts and active policy, and fences shared state with SQLite transactions. |
| [baseline_bridge.py](baseline_bridge.py) | Verifies the frozen catalog and invokes the original HMAC authority port and the sovereign tool adapter after admission. |

New capabilities start off. Enable requires an installed binding with the declared contract hash and an authorized caller. Disable immediately blocks new reservations and lets already admitted calls finish. Remove requires off mode and no unresolved calls. Removal persists as a tombstone, including across restart and policy activation. The host can uninstall the plug-in package separately.

Activation is a host operator action using the approved policy digest. A higher policy generation fences older sessions and requires fresh enablement for previously enabled tools. Use a protected state directory shared by the trusted launchers. POSIX demo files use private permissions. On Windows, place the demo under a private inherited ACL. The stdio launcher binds a principal to its credential. MCP frames carry no identity, role, or attribute authority.

SQLite retains hashed lifecycle, admission, and outcome receipts. An invocation reserves a durable lease before reaching the handler. An uncertain handler outcome leaves the lease unresolved and blocks new work and removal for that capability. This release has no automatic reconciliation or forced removal. The host controls filesystem access to the ledger. Its SHA-256 links are integrity evidence, with authenticity dependent on retaining an independent trusted receipt.

## Connect the sovereign baseline

The frozen definitions in [baseline_catalog.json](baseline_catalog.json) come byte-for-byte from the supplied MCP+ archive. Each authenticated session uses the same baseline contract. The sovereign authority still controls visibility and admission, including for write, command, and Git tools. A baseline call uses a fresh reservation ID, validates against the frozen schema, and records its authenticated sovereign admission before dispatch. The bridge uses the original authority and tool ports, with receipts in the shared registry ledger.

The supplied subprocess adapters require POSIX. Extract the pinned wheel from the user-supplied archive, then install it without changing the locked dependencies.

```sh
python extract_upstream.py /path/to/hmt-mcp-plus-server-kernel_v1.0.0.zip
python -m pip install --no-deps local-upstream/hmt_mcp_plus_server_kernel-1.0.0-py3-none-any.whl
HMT_TEST_SOVEREIGN=1 python -B -W error -m unittest -v
```

For a configured baseline, set the applicable principal’s `baseline_config_sha256` in TOML and pass the matching operator-owned JSON with `--baseline-config`. The original kernel configuration contract supplies the sovereign adapter and bound principal. The authority process may receive only its configured HMAC environment variable. Sovereign tool processes receive no inherited variables through the bridge’s allowlist. Keep demo and test credentials out of deployment.

## Qualification scope

Run `python -B -W error -m unittest -v` for registry and stdio tests. The opt-in POSIX test uses the original packaged adapters with a signed test authority and a harmless `list_files` fixture. It checks the exact 13-tool discovery surface and verifies that revoking authority after discovery blocks the next effect. Production authority bindings and remote HTTP transport require separate integration.

Reference artifacts are the supplied MCP+ server kernel v1.0.0 and the HMT v1.7.15 PolicyEngine and CapabilityRegistry. The bridge retains strict schema checks and sovereign admission from MCP+. The registry follows HMT’s role-and-attribute checks, off-by-default binding, lifecycle generations, and removal after settlement. [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) · [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
