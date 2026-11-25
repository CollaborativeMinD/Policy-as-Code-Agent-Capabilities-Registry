# Working in this repository

Read the [README](README.md#change-the-system-through-policy) for the workflow. Use the [Runbook](Runbook.md) for commands and [SKILL.md](SKILL.md) for the policy change loop.

1. State the requested effect and the expected denial. Edit TOML first.
2. Run the candidate in a test state. If the runtime already enforces it, keep the patch in policy.
3. For missing behavior, reproduce the failed admission. Find the owning model, binding, or runtime guard. Add only the missing piece.
4. Rerun the same allow and deny cases. Check the actual effect, active policy digest, and receipt.
5. Run the release gate for the exact commit. Report the result and any unresolved part. Stop when the evidence matches the policy.

Keep the frozen baseline catalog intact. Let the sovereign authority admit baseline calls. Recheck RBAC, ABAC, and current registry mode for plug-in calls. Keep management scopes separate from invocation. Keep credentials and local state out of commits.

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.
