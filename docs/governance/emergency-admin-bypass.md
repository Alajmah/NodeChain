# Emergency Admin Bypass Procedure

**Document class:** Exceptional governance procedure  
**Normal qualification authority:** branch protection + `docs/ci.md`

## When to use

An admin bypass is a temporary, narrowly scoped relaxation of branch protection used only when an external constraint prevents an otherwise qualified change from proceeding through the normal protected PR → hosted checks → squash-merge path.

The solo-maintainer zero-approval policy exists specifically to avoid routine bypasses. A bypass should be exceptional, not an alternative daily workflow.

## Conditions

All of the following must be true before a bypass is used:

1. The change has satisfied the mandatory qualification that normally applies to it, except for the specific external/platform constraint that makes the protected operation impossible.
2. The exact branch-protection-required hosted check set is evaluated from the current configuration; do not rely on a stale hard-coded check count.
3. Any additional capability-qualified evidence required by the change (for example privileged native-containment proof) has been satisfied or the emergency risk/deferral is explicitly documented.
4. The change is understood and its changed-file boundary is reviewable.
5. The bypass is the minimum protection relaxation needed.
6. The bypass duration is as short as practical — normally one controlled operation.

## Procedure

1. **Document** the blocking constraint and why the normal protected action cannot complete.
2. **Capture** the relevant pre-bypass protection state.
3. **Apply** only the minimum required relaxation.
4. **Perform** the intended merge/recovery operation.
5. **Restore** full branch protection immediately.
6. **Capture** the post-restore protection state.
7. **Record** the reason, timing, affected setting, PR/commit, merge SHA, and restoration evidence.
8. **Run/confirm** any post-operation verification needed to ensure the accepted `master` state is the state that was qualified.

## What an admin bypass is NOT

- It is not a way to skip failed CI.
- It is not a way to relabel a capability-sensitive hosted check as privileged security proof.
- It is not a way to merge unreviewed or unknown changes.
- It is not a substitute for the solo-maintainer zero-approval policy.
- It does not authorize force pushes, branch deletion, retention destruction, or unrelated policy relaxation.
- It does not convert a different commit's qualification evidence into evidence for the merged commit.

## Evidence to retain

- bypass reason and external constraint;
- PR/change identity;
- candidate SHA and resulting `master` SHA;
- protection state before, during, and after the bypass;
- timestamps/duration;
- hosted qualification evidence relevant to the change;
- any additional native/security qualification evidence required by the change;
- post-restore verification.

## Destructive-retention exclusion

An admin bypass is repository governance only. It does **not** start the seven-day destruction clock and does not authorize B6 or any other destructive retention action.
