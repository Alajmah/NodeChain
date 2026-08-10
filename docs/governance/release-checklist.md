# Release Checklist

**Document class:** Release governance  
**Authoritative hosted-check definition:** `docs/ci.md`, `.github/workflows/ci.yml`, `.github/workflows/publication-tree.yml`, and branch protection

This checklist governs every public NodeChain release.

Do not hard-code an independent “N/N checks” contract here. The mandatory check set is whatever branch protection requires for the exact release-candidate/release commit, with the semantics documented in `docs/ci.md`.

---

## Pre-release

1. Confirm the release PR targets `master` and contains only release-scoped changes plus any explicitly accepted feature/documentation changes intended for that release.
2. Confirm every branch-protection-required hosted check for the exact release-PR head satisfies protection.
3. Confirm the Publication Tree matrix required by branch protection has completed successfully for the exact candidate SHA.
4. If the release makes a privileged/native containment claim not established by hosted CI, confirm the separately required capability-qualified evidence is attached to the same candidate.
5. Confirm the working tree/release source is reproducible from the canonical repository and contains no required untracked source, schema, fixture, migration, or specification material.
6. Confirm release notes/changelog describe the candidate actually being released, not a later development baseline.

---

## Merge

7. Squash-merge the release PR according to the public development policy.
8. Record the resulting `master` commit SHA and tree identity/equivalent source identity required by the release evidence process.

---

## Post-merge verification

9. Wait for the push-triggered branch-protection-required hosted checks on the resulting `master` release commit to complete as required.
10. Confirm the release commit is the exact commit intended for tagging and packaging.
11. If any source-affecting correction is required after merge, treat the corrected commit as a new release candidate and repeat affected qualification; do not tag evidence from the previous SHA.

---

## Artifact proof

12. Build release artifacts from the verified `master` release commit.
13. Confirm exactly one intended wheel and one intended sdist are produced.
14. Install the wheel into an empty virtual environment.
15. Build/install or otherwise verify the sdist according to the release procedure.
16. Verify `nodechain --version` reports the release version.
17. Run the release CLI smoke surface.
18. Confirm required runtime schemas are present in installed artifacts and match the publication contract.
19. Record SHA-256 checksums of the wheel and sdist.
20. Record any additional signed manifests/attestations required by the release.

---

## Tag and publish

21. Create the intended release tag (`vX.Y.Z`) on the verified `master` release commit.
    - Do not tag a feature-branch commit, PR pseudo-ref, or a commit whose release checks/artifacts were not the accepted evidence source.
22. Publish the GitHub release.
23. Attach checksums, release notes, and required evidence references.
24. Preserve the release evidence bundle.

---

## Evidence to retain

Retain at least:

- release PR and accepted head SHA;
- final `master` release SHA;
- required hosted check run IDs/conclusions or equivalent GitHub evidence;
- Publication Tree evidence;
- capability-qualified native/security evidence when the release claim requires it;
- wheel and sdist SHA-256 checksums;
- empty-environment installation and CLI/schema smoke output;
- release tag identity;
- release notes/changelog state;
- any branch-protection snapshot required by governance.

---

## Release truth rules

- A green hosted check set proves only the evidence class described in `docs/ci.md`.
- `slow-shard-2` is capability-sensitive and job-level tolerant; it is not a substitute for privileged Linux containment qualification.
- A development-baseline feature merged after the last release is not part of that past release merely because `nodechain.__version__` has not yet been bumped.
- Release notes are historical records after publication; later master changes do not alter what the release contained.

---

## Exclusions

- Releases do not start the seven-day destruction clock.
- Releases do not authorize B6 or any destructive retention action.
- No private-history objects or references may appear in public release artifacts.
- Ordinary release activity does not authorize weakening branch protection or containment requirements outside the separately governed emergency procedure.
