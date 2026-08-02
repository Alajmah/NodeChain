# Release Checklist

This checklist governs every public release of NodeChain.

## Pre-release

1. Confirm the release PR targets `master` and contains only release-scoped
   changes (version metadata, changelog, release notes, manifest files).
2. Confirm the release PR has passed all mandatory hosted checks:
   - CI: 10/10 jobs success.
   - Publication Tree: Ubuntu + Windows success.
3. Confirm the working tree is clean.

## Merge

4. Squash-merge the release PR.
5. Record the resulting `master` SHA and tree SHA.

## Post-merge verification

6. Wait for push-triggered master workflows to complete green:
   - CI: 10/10 jobs success.
   - Publication Tree: Ubuntu + Windows success.
7. Verify the master SHA and tree match expectations.

## Artifact proof

8. Confirm exactly one wheel and one sdist are produced.
9. Install the wheel in an empty virtual environment.
10. Build and install the sdist.
11. Verify `nodechain --version` reports the correct version.
12. Run the CLI smoke test.
13. Confirm the package contains required schemas.
14. Record SHA-256 checksums of the wheel and sdist.

## Tag and publish

15. Create an annotated tag (`vX.Y.Z`) on the verified master SHA.
    - Do not tag the feature-branch commit or PR pseudo-ref.
16. Publish the GitHub release.
17. Attach checksums and release notes.
18. Preserve the release evidence bundle.

## Evidence to retain

- Source commit SHA and tree SHA.
- CI and Publication Tree run IDs and conclusions.
- Wheel and sdist SHA-256 checksums.
- Installation and smoke-test output.
- Tag SHA.

## Exclusions

- Releases do not start the seven-day destruction clock.
- Releases do not authorize B6 or destructive retention actions.
- No private-history objects or references may appear in release artifacts.
