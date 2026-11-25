# Runbook

Start with the policy. Follow the same path for a one-line grant change and a new capability.

## 1. Define the change

Open [policy.example.toml](policy.example.toml) for the declaration shape. Edit the real candidate TOML. Name the tool, scope, role, attributes, and expected effect. Name one request that should pass and one that should be denied. Increase `generation` for a new policy revision.

If the runtime already supports the change, keep the patch in TOML. A role grant, a tenant match, or a deny rule needs no new handler.

## 2. Watch admission

Use a test state and test credentials. The [README demo](README.md#run-the-local-demonstration) gives you both. Keep one state database across candidate generations when you need to test revocation or a tombstone.

```powershell
$policyHash = (Get-FileHash -Algorithm SHA256 local-demo/policy.toml).Hash.ToLowerInvariant()
python server.py activate --policy local-demo/policy.toml --policy-sha256 $policyHash --state local-demo/state.sqlite
python -B -W error -m unittest -v
```

The hash command computes a test pin. For promotion, take the approved digest from the release record. Restart the client with the resulting pin. Check the capability’s state with `capabilities.status`. A new policy generation starts installed capabilities off. Enable the test capability if the case calls for it, then attempt the exact call you wrote down.

| Result | What to check next |
| --- | --- |
| `CAPABILITY_DENIED` | Check the active generation, mode, role scope, and attributes. Follow deny overrides. |
| `CAPABILITY_NOT_READY` | Check that the trusted plug-in is installed and that no call is unsettled. |
| `BINDING_PIN_MISMATCH` | Compare the installed plug-in ID and schema digest with the declaration. |
| `GENERATION_CONFLICT` | Read status again. Review the intervening change before issuing a new request. |
| `POLICY_STALE` | Reconnect with the active policy’s pin. |
| `BASELINE_HOLD` | Check the separately pinned sovereign adapter configuration and authority status. |

## 3. Add a missing behavior

Declare the desired contract in TOML first. Run the rejected case before writing the handler. A validated declaration without a host binding must stay off.

Implement the smallest missing piece. Put the argument contract in a strict Pydantic `BaseModel`. Add the handler and its binding in [plugins.py](plugins.py). Extend [policy_engine.py](policy_engine.py) or [capability_registry.py](capability_registry.py) only when the policy calls for new enforcement behavior. Publish the reviewed binding’s contract digest in TOML.

Run the same case again. Then run the denied case. Confirm that denial leaves the effect absent. For a missing binding, the test `test_policy_declared_capability_holds_until_host_binds_it` shows the full boundary.

## 4. Qualify and promote

Push the candidate revision to the workstation Forgejo remote. Wait for Linux and Windows packaging and AMD64 and ARM64 Compose to pass. Match the run to the exact commit. Read back the signed reports and the distributions before publishing the same SHA. [Qualification workflow](.forgejo/workflows/distribution.yml)

Compare the observed effect, lifecycle generation, and receipt with the candidate policy. Record the commit, policy digest, and result. The host operator applies the approved digest with `server.py activate`. Relist tools and recheck the intended effect. Stop when the policy and evidence agree.

## Disable or remove

Read status before each change. Disable first to stop new calls. Wait for pending calls to settle. Use the current generation to remove the capability. Removal records a tombstone.

An uncertain result leaves a pending lease. Inspect the capability’s external state and the admission receipt before recovery. Keep removal blocked while the outcome is unknown. The service provides no forced-removal operation.

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.

## From policy change to release

Start with [policy.example.toml](policy.example.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `python -B -m unittest -v` in the project environment. Exercise the normal entry point and the denial. Review the capability disposition and settled receipt. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.

The version 2 `[runtime]` table in `console.toml` sets request size, concurrency and client deadlines. Version 1 files inherit the shipped budget. Reissue them as version 2 to pin these choices in the admitted document.

Set registry contention time in `ledger_wait_seconds` in [policy.example.toml](policy.example.toml). The registry validates the value with the grant declaration before opening its ledger.
