# Emergency Admin Bypass Procedure

## When to use

An admin bypass is the temporary relaxation of branch protection rules to
unblock a merge that cannot proceed under normal rules. It is **exceptional**,
not a routine workflow.

The solo-maintainer zero-approval policy exists specifically to avoid the need
for admin bypasses during ordinary development. A bypass should only be needed
when an external constraint (e.g., a GitHub platform limitation or an urgent
security fix) prevents the standard PR → CI → squash-merge path.

## Conditions

All of the following must be true before a bypass is used:

1. The PR has passed all mandatory hosted checks (CI 10/10, Publication Tree 2/2).
2. The PR has been reviewed and the change is understood.
3. The bypass is the minimum change needed (e.g., temporarily setting
   `required_approving_review_count` to 0, not disabling protection entirely).
4. The bypass duration is as short as possible — typically a single merge
   operation.

## Procedure

1. **Document** the reason for the bypass (what constraint prevented normal
   merge).
2. **Apply** the minimum protection relaxation needed.
3. **Merge** the PR using squash.
4. **Restore** branch protection to its full state immediately.
5. **Capture** a post-restore protection snapshot showing all rules are active
   again.
6. **Record** the bypass reason, duration, merge SHA, and restoration snapshot
   in the audit trail.

## What an admin bypass is NOT

- It is not a way to skip CI or Publication Tree.
- It is not a way to merge unreviewed or unqualified changes.
- It is not a substitute for the solo-maintainer zero-approval policy.
- It does not authorize force pushes or branch deletion.

## Evidence to retain after a bypass

- Bypass reason and constraint description.
- PR number and merge SHA.
- Protection state before bypass, during bypass, and after restoration.
- Timestamp of restoration.
