---
name: hmt-capability-policy
description: Change or qualify an HMT MCP capability, grant, attribute rule, or lifecycle transition. Use the TOML contract to drive admission and implement runtime behavior only when the policy requires a missing model, binding, or guard.
---

# Change capability policy

Read [the runbook](Runbook.md) when you need a command or a denial code.

1. Name the effect and the request that must be denied. Change TOML first. Increase the policy generation.
2. Run the candidate in an isolated test state. If existing enforcement gives the right result, keep the change in TOML.
3. For a missing behavior, keep the failing admission as evidence. Implement the strict model, trusted binding, or guard named by the policy. Rerun the same case.
4. Check the allowed effect and its receipt. Check that the denied case produced no effect. Compare both with the policy digest and generation.
5. Qualify the exact commit. Stop when policy, runtime, and evidence agree.

Use `CAPABILITY_NOT_READY` to trace a missing binding or unsettled call. Use `CAPABILITY_DENIED` to trace mode, scope, or attributes. Preserve sovereign baseline admission, deny overrides, separate management scopes, and removal tombstones. Keep activation with the authorized host operator.

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.
