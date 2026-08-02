# Public Development Policy

## Repository

NodeChain is developed publicly at `github.com/Alajmah/NodeChain` under the MIT
license.

## Solo-maintainer mode

NodeChain is currently maintained by a single developer. GitHub does not permit
self-approval of pull requests, so requiring one approving review would make
merging impossible without disabling and restoring branch protection around
every merge — an unsustainable and audit-unfriendly practice.

Therefore:

- **Required approving reviews: 0** while in solo-maintainer mode.
- Pull requests remain **required** for all changes to `master`.
- All mandatory hosted CI checks remain **required**.
- When an independent trusted reviewer is available, required approvals
  **must return to 1**.

## Merge policy

- **Squash merge** is the only permitted merge method.
- Merge commits and rebase merges are disabled.
- Linear history is required.

## Required hosted checks

Every pull request must pass before merge:

- **CI** — all 10 jobs (lint, unit-fast, orchestrator-recovery, trust-collector,
  slow-shard-1/2/3, cli-smoke, package-build, windows-tests).
- **Publication Tree** — both Ubuntu and Windows matrix jobs.

Windows tests are a **blocking** gate (no `continue-on-error`).

## Branch protection

The following protections are enforced on `master` and must remain active:

- Pull request required.
- Force pushes disabled.
- Branch deletion disabled.
- Linear history required.
- Administrators enforced.

## Admin bypass

An admin bypass (temporarily relaxing branch protection to merge) is
**exceptional** and must satisfy all of the following:

1. The PR has passed all mandatory hosted checks.
2. The bypass is the minimum change needed to unblock the merge.
3. The bypass is documented with the reason, duration, and restoring action.
4. Branch protection is restored **immediately** after the merge.
5. A post-restore protection snapshot is captured and retained as evidence.

Admin bypass should not become standard practice. The solo-maintainer
zero-approval policy exists to avoid the need for routine bypasses.

## Changed-file boundary

Every PR must report its changed-file boundary (path list and additions/deletions)
in the PR description or review evidence. Unrelated changes must not be bundled
into a PR.

## Destructive actions

B6 (retention destruction) and other destructive retention actions are
**outside ordinary development governance**. They require separate, explicit
authorization and are not triggered by development or release activity.

The seven-day destruction clock is **not started** by ordinary development,
release activity, or any action described in this policy.

## Evidence retention

The following must be preserved until explicitly authorized for destruction:

- Private archive repository.
- Reconstruction bundles and qualification logs.
- ct801 host evidence and diagnostic records.
- Branch-protection snapshots.
- Release evidence bundles.
