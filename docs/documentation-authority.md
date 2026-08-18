# NodeChain Documentation Authority

**Document class:** Governance / documentation control  
**Status:** Active  
**Established:** 2026-08-10

NodeChain documentation had accumulated strategic, normative, historical, release-specific, and current-state claims in the same files. This document defines the classes and update rules that prevent those truth domains from drifting together again.

---

## 1. Document classes

Every important NodeChain document should be understandable as one of these classes.

### NORMATIVE

Defines what **must** be true for the architecture, protocol, contract, invariant, or product boundary.

Examples:

- NodeChain System Specification;
- versioned JSON schemas;
- explicitly frozen/public contracts;
- accepted invariant specifications.

Normative documents are not implementation-status reports. The code may be partial relative to a normative target; that gap belongs in the baseline/roadmap rather than silently weakening the specification.

### DESCRIPTIVE

States what **is actually true in the code at a pinned baseline**.

Examples:

- `BASELINE.md`;
- `ARCHITECTURE.md`;
- deployment-profile descriptions that claim current behavior.

Descriptive documents must identify a date and/or commit baseline when the claim is materially code-dependent.

### STRATEGIC

Explains why NodeChain exists, its product thesis, intended users, positioning, and long-term direction.

Example:

- `VISION.md`.

Strategic documents should avoid volatile file counts, test counts, current SHAs, and release-by-release implementation inventories.

### ROADMAP

Contains unfinished outcomes only.

Example:

- `ROADMAP.md`.

Completed work moves to the changelog/release history and baseline. A roadmap should not become a permanent archive of checked-off versions.

### RELEASE RECORD

Records what was included and qualified for a specific release.

Examples:

- `CHANGELOG.md` release sections;
- `docs/releases/vX.Y.Z.md`;
- release evidence bundles.

A release record is historical after release. Later development must not be back-projected into it.

### HISTORICAL

Preserves an earlier design or implementation snapshot for context.

Examples:

- the original Research & Decision Assistant Reference Implementation;
- historical architecture reports;
- superseded correction roadmaps.

Historical documents should identify the period/version they describe and point readers to `BASELINE.md` for current truth.

### EVIDENCE

Records the result of a concrete qualification, test, deployment, benchmark, review, or host-specific proof.

Examples:

- privileged native-sandbox verification reports;
- CI evidence;
- external verification bundles;
- baseline comparison artifacts.

Evidence must name the exact code/artifact and environment/profile it proves. Evidence from one profile must not be generalized to another without an explicit argument and qualification.

---

## 2. Current authority map

| Question | Authority |
|---|---|
| What does the current development code actually support? | `BASELINE.md` + code at its pinned SHA |
| How is the current code arranged? | `ARCHITECTURE.md` + code at its pinned SHA |
| Why does NodeChain exist / what is it becoming? | `VISION.md` |
| What remains to be built or corrected? | `ROADMAP.md` |
| What changed in a release? | `CHANGELOG.md` + `docs/releases/*` |
| What should the complete platform mean? | NodeChain System Specification |
| What did the original research chain design require? | Original Reference Implementation |
| What does CI actually prove? | `.github/workflows/*` + `docs/ci.md` |
| What does a deployment/security proof establish? | The named evidence document at its exact code/environment baseline |
| What does deployment profile X support? | `docs/deployment-profiles.md` (canonical matrix) + the exact evidence it names |

---

## 3. Precedence rules

For a **current descriptive claim**:

```text
actual code / schema / workflow at pinned SHA
        ↓
BASELINE.md
        ↓
current ARCHITECTURE / deployment docs
        ↓
README summaries
```

If a descriptive document conflicts with code, the document is stale and must be corrected.

For a **normative requirement**:

```text
accepted normative specification / schema / invariant contract
        ↓
implementation mapping
        ↓
code status
```

A code gap does not automatically rewrite the normative requirement.

For **release history**:

```text
release/tag/artifact evidence
        ↓
release notes / changelog section
```

Later master changes do not alter what a past release contained.

---

## 4. Baseline update protocol

A feature merge should trigger a documentation rebaseline only when it materially changes product or architecture truth.

When rebaseline is needed:

1. identify the exact new `master` SHA;
2. trace the affected runtime/product path in code;
3. update `BASELINE.md` first;
4. update `ARCHITECTURE.md` if execution/data/authority boundaries changed;
5. update `README.md` only for user-facing entry-point changes;
6. update `ROADMAP.md` by removing completed outcomes and adding only demonstrated/newly authorized future outcomes;
7. update `CHANGELOG.md` under `[Unreleased]` for releasable changes;
8. update profile/CI docs only from the actual workflow/code that implements them.

Do not rewrite `VISION.md` for routine release changes.

---

## 5. Rules for volatile facts

Avoid manually maintained global counts unless they are generated or required evidence.

Examples of volatile claims:

- number of CLI commands;
- number of Python files/modules;
- number of tests;
- number of schemas;
- file sizes;
- CI duration estimates;
- branch protection check counts;
- current commit SHA.

When a count is operationally important, prefer:

- the authoritative workflow/configuration;
- a generated manifest;
- a pinned evidence report;
- exact command output captured for the relevant release.

Do not use an old count as a proxy for maturity.

---

## 6. Security and containment documentation rule

Every security/containment claim must identify the **execution path** and **qualification profile**.

For example, these are different claims:

- native command runner enforced seccomp under a privileged Linux verification host;
- supervised argv substrate established PID-namespace/ptrace lifecycle ownership;
- generic Harness Node invocation routes untrusted POSIX nodes through that substrate;
- GitHub-hosted tests passed.

One does not imply the others.

Security documentation must state whether a path is:

- enforced;
- unavailable/fail-closed;
- capability-sensitive;
- experimental/prototype;
- historical evidence only.

---

## 7. Product-proof documentation rule

A deterministic fixture proof, mock-model proof, real-model proof, live-network proof, user study, and production deployment are different evidence classes.

Documentation should say which one occurred.

For the Research Workspace, for example:

- the sealed fixture corpus proves deterministic governed execution and evidence continuity;
- it does not by itself prove live-source reliability;
- a live-source profile should reuse the same evidence/bundle semantics but will have different reproducibility properties.

---

## 8. Historical-document preservation

Historical documents should not be deleted merely because they are no longer current; they are valuable evidence of design evolution.

They should, however, be clearly labeled and should not occupy the current-truth authority position.

Where a root document must become current (for example `ARCHITECTURE.md`), the old state remains recoverable through git history/release tags and may additionally be copied into a `docs/history/` archive when useful.

---

## 9. Release documentation discipline

Before release:

- `[Unreleased]` describes changes since the last release;
- `BASELINE.md` may describe additional development state but must distinguish it from the last released version.

At release:

- freeze the release notes to the verified release commit/artifacts;
- move applicable `[Unreleased]` content under the new version;
- update the released-version field in `BASELINE.md` only after release truth is established;
- do not modify old release sections to include later work.

---

## 10. Review checklist for important documentation changes

A documentation review should ask:

- What class is this document?
- Is it making normative, descriptive, strategic, historical, or evidence claims?
- If descriptive, what exact code baseline supports it?
- If evidence, what exact execution path/environment does it prove?
- Does it accidentally use a past release as current development truth?
- Does it conflate fixture/mock evidence with live/production evidence?
- Does it claim a sandbox/integration path that the generic runtime does not actually use?
- Does it duplicate volatile counts that can drift independently?
- Is completed roadmap work being retained as future work?
- Does another document already own this question?

The goal is not more documentation. The goal is **one clear authority for each kind of truth**.
