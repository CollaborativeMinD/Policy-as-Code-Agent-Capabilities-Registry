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

## From policy change to release

Start with [policy.example.toml](policy.example.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `python -B -m unittest -v` in the project environment. Exercise the normal entry point and the denial. Review the capability disposition and settled receipt. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.
