# Public Development Policy

**Document class:** Development governance  
**Authoritative CI semantics:** `docs/ci.md` and branch protection

## Repository

NodeChain is developed publicly at `github.com/Alajmah/NodeChain` under the MIT license.

## Solo-maintainer mode

NodeChain is currently maintained by a single developer. GitHub does not permit self-approval of pull requests, so requiring one approving review would make merging impossible without routinely disabling and restoring branch protection — an audit-unfriendly operating model.

Therefore:

- **Required approving reviews: 0** while in solo-maintainer mode.
- Pull requests remain required for ordinary changes to `master`.
- Every branch-protection-required hosted check remains required according to the configured protection/workflows.
- When an independent trusted reviewer is consistently available, the review requirement should be reconsidered rather than relying on routine admin bypasses.

## Merge policy

- **Squash merge** is the intended normal merge method.
- Merge commits and rebase merges remain disabled under the current repository configuration.
- Linear history is required.
- Force pushes and branch deletion remain disabled on the protected default branch.

## Required hosted checks

Every pull request must satisfy the exact hosted check set required by branch protection for its head SHA before normal merge.

The authoritative current check names and their evidence semantics are documented in `docs/ci.md` and implemented in:

- `.github/workflows/ci.yml`
- `.github/workflows/publication-tree.yml`

Do not maintain a separate hard-coded “10/10 + 2/2” contract in governance documents. Job counts can change; required check identities and workflow semantics are the authority.

Windows tests remain part of the protected cross-platform surface. Capability-sensitive Linux security checks must be interpreted according to their actual workflow semantics; a required check name does not automatically mean a privileged capability was exercised.

## Branch protection

The following protections are expected to remain active on `master` under ordinary operation:

- pull request required;
- strict required status checks;
- force pushes disabled;
- branch deletion disabled;
- linear history required;
- administrators subject to protection (`enforce_admins`).

Repository configuration is the technical authority; this document states the operating policy.

## Changed-file boundary

Every PR must report or make reviewable its changed-file boundary. Unrelated changes should not be bundled merely because they can pass the same CI run.

For large coordinated waves (for example a documentation rebaseline), the PR may span multiple files when they serve one explicitly stated objective and the changed-file boundary remains inspectable.

## Evidence discipline

A PR description/review should distinguish:

- local targeted evidence;
- local broad/full-suite evidence;
- hosted protected-check evidence;
- Publication Tree evidence;
- capability-qualified native/security evidence;
- product/user evidence.

Do not describe one evidence class as another.

## Admin bypass

An admin bypass — temporarily relaxing protection to unblock a merge — is exceptional and must satisfy all of the following:

1. The change has satisfied the mandatory qualification that would normally govern it, except for the external/platform constraint causing the bypass.
2. The bypass is the minimum relaxation needed.
3. The reason, duration, affected protection setting, and merge are documented.
4. Branch protection is restored immediately after the operation.
5. A post-restore protection snapshot/equivalent evidence is retained.

Admin bypass is not a substitute for normal solo-maintainer governance and must not become the standard merge path.

## Emergency changes

Urgent security/recovery work may require a narrower emergency procedure, but urgency does not convert missing evidence into evidence. Any bypassed normal step must be documented and followed by the strongest feasible post-change verification.

## Destructive actions

B6 (retention destruction) and other destructive retention actions are **outside ordinary development governance**. They require separate, explicit authorization and are not triggered by development, documentation, merge, CI, release, or repository-maintenance activity.

The seven-day destruction clock is **not started** by any ordinary activity described in this policy.

## Evidence retention

Preserve governance/release evidence until separate retention/destruction authority says otherwise, including as applicable:

- private archive/reconstruction material retained by policy;
- qualification logs and evidence bundles;
- capability-host diagnostic/verification records;
- branch-protection snapshots;
- release evidence bundles;
- exceptional bypass records.

## Documentation authority

Current implementation claims belong in `BASELINE.md`; strategic direction belongs in `VISION.md`; future work belongs in `ROADMAP.md`; release history belongs in `CHANGELOG.md`/release records.

See `docs/documentation-authority.md` for the classification and precedence rules.
