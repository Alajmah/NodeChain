# NodeChain Roadmap — Post-Rebaseline

**Document class:** Future work  
**Baseline date:** 2026-08-17  
**Baseline SHA:** `068120f6a46797182d33e100b5dadfc8ccc77b4f`  
**Current released version:** `v3.6.0`  
**Current implementation truth:** [BASELINE.md](BASELINE.md)

This roadmap contains **unfinished outcomes only**. Shipped release history belongs in `CHANGELOG.md`; current-state claims belong in `BASELINE.md`; normative platform semantics belong in the System Specification.

The roadmap is organized by outcomes rather than pre-assigned release numbers. A release may close one or more outcomes, but version numbering is not itself progress.

---

## Roadmap rules

1. **Every item must close a concrete product, authority, qualification, or usability gap.**
2. **Already-proven behavior is not reopened merely because a stronger implementation is imaginable.**
3. **Trace, state, side-effect, trust, and containment claims must be backed by runtime evidence, not configuration alone.**
4. **A stronger control may fail closed; it must not silently degrade to a weaker path.**
5. **Product work should consume the existing runtime before inventing a new execution substrate.**
6. **Documentation that describes current behavior must be pinned to a code baseline and updated when the baseline materially changes.**
7. **New roadmap gates require a demonstrated defect, unmet product outcome, or explicit strategic decision.**

---

# Horizon 0 — Baseline and authority closure

**Objective:** remove the remaining contradictions that prevent NodeChain from making a literal “one governed execution truth” claim across the important production and product-proof paths.

These are bounded corrections identified by the current code/document rebaseline. They are not a new platform expansion phase.

## H0.6 — Deployment profile truth

**Required outcome**

Documentation and qualification distinguish at least:

- trusted local development;
- GitHub-hosted cross-platform CI;
- privileged Linux containment verification;
- generic POSIX untrusted-node execution;
- Windows control-plane/development behavior;
- future production delegated/managed execution.

No document may use evidence from one profile to imply qualification of another.

---

# Horizon 1 — Governed Research Workspace productization

**Objective:** turn the accepted research product-proof backend into a coherent user product without weakening the runtime/evidence contract.

## H1.1 — Workspace object model

Provide a stable user-facing concept of a Workspace containing:

```text
brief / objective
plan
runs
sources
qualified sources
evidence
claims
citations
uncertainties
faults and recovery
review decisions
trace
terminal verified bundles
```

The Workspace should be a projection over authoritative runtime/evidence records, not an independent truth store.

## H1.2 — Research operator experience

Build a coherent CLI/API/UI flow for:

- create/open workspace;
- launch research run;
- inspect progress;
- review pending decisions;
- inspect sources/evidence/claims;
- understand faults/degraded completion;
- resume/recover;
- verify/download final bundle;
- compare runs.

The current `research run` / `research review` commands are the starting substrate, not the final UX.

## H1.3 — Live source acquisition profile

Add a product profile that applies the Research Workspace evidence/bundle semantics to live source acquisition rather than the sealed fixture corpus.

Required properties:

- live adapters preserve the same provenance/version contract;
- qualified-source identity is bound to actual ingested artifacts;
- fault records remain projections of actual runtime evidence;
- network/source variability is explicit in reproducibility claims;
- sealed fixture mode remains available for deterministic qualification.

## H1.4 — Human-readable final research artifact

The terminal bundle should support a first-class user-facing report/memo view that is derived from the same claims, evidence, citations, risk, review, failure, and trace records.

The product should make governance evidence understandable without requiring raw JSON inspection.

## H1.5 — Product proof with users

Run structured product proof against real research tasks and evaluate:

- time to useful result;
- source/evidence inspectability;
- reviewer comprehension;
- trust in citations and uncertainty;
- usefulness of fault/recovery visibility;
- repeatability across runs;
- perceived governance overhead vs value.

This is product proof, not a new runtime gate.

---

# Horizon 2 — Governed evaluation as a runtime-level quality system

**Objective:** connect evaluation to the same execution truth used by production runs.

## H2.1 — Full-runtime evaluation runner

Provide an evaluation runner that executes the complete governed chain/runtime when a metric depends on:

- policy decisions;
- side effects;
- recovery/retry;
- review;
- persistence;
- trace completeness;
- trust/containment;
- runtime cost/latency.

Direct-node deterministic evaluators may remain for node-quality tests, but their evidence class must remain explicit.

## H2.2 — Evaluation evidence binding

An evaluation result should identify:

- target package/blueprint/version/digest;
- execution profile;
- run IDs and trace IDs;
- evidence/bundle references;
- metric inputs;
- evaluator version;
- policy/invariant set;
- pass/fail thresholds.

## H2.3 — Regression and release gates

Promote stable runtime-level evaluations into regression gates only after their evidence contract and reproducibility are characterized.

Avoid turning every useful metric into a blocking release check.

---

# Horizon 3 — Enterprise foundation

**Objective:** make the local governed runtime suitable as the execution core of an organizational platform.

## H3.1 — Organization and identity model

- organizations/workspaces/projects;
- users/service identities;
- roles and scoped authority;
- reviewer identity and delegation;
- audit identity continuity.

## H3.2 — Multi-tenant isolation

Define and prove isolation for:

- state databases;
- traces/evidence;
- package registries;
- secrets/credentials;
- memory/vector stores;
- connector access;
- policy configuration;
- execution workers.

## H3.3 — Secrets and connector governance

Connect external systems through explicit credential scopes, capability grants, audit events, rotation, and revocation. Connector trust must remain separate from node/package trust.

## H3.4 — Retention and compliance controls

- evidence retention policies;
- legal hold / deletion authority;
- export/audit bundles;
- data classification;
- policy/version history;
- tenant-level compliance evidence.

## H3.5 — Scale and service qualification

Measure and qualify:

- concurrent runs;
- queueing/backpressure;
- state contention;
- trace volume;
- recovery under worker loss;
- latency/cost envelopes;
- SLOs and operator failure modes.

Do not infer service scalability from unit-test volume.

---

# Horizon 4 — Node ecosystem and Blueprint Studio

**Objective:** make governed reuse a daily developer/operator workflow rather than an internal capability.

## H4.1 — Private Registry product surface

Productize the existing registry/trust substrate into a coherent organizational catalog:

- search/discovery;
- package/version detail;
- trust/certification status;
- dependency graph;
- compatibility;
- deprecation/revocation;
- installation/admission policy;
- usage/evaluation history.

## H4.2 — Node authoring experience

Provide a low-friction path from:

```text
create → implement → validate → test → evaluate → package → sign → publish → reuse
```

with generated contracts/manifests only where the generated result remains explicit and reviewable.

## H4.3 — Blueprint Studio

Expose composition with governance context:

- contract/typed-port graph;
- requirements and adapter grants;
- trust posture;
- side-effect map;
- review gates;
- loops/branches;
- cost/risk overlays;
- validation/preflight;
- execution simulation;
- evidence expectations.

The Studio must compile to the same blueprint/runtime authority rather than become a second workflow engine.

---

# Horizon 5 — Visual builder, managed execution, and ecosystem

**Objective:** expand distribution and usability after the execution/evidence model is stable enough to survive broader use.

Potential outcomes:

- graphical typed-port composition;
- managed NodeChain execution service;
- governed remote worker pools;
- organization-wide policy distribution;
- certified node program;
- controlled blueprint sharing/marketplace;
- third-party node ecosystem;
- enterprise assurance dashboards;
- cross-workspace reusable evidence and evaluation assets.

These are strategic directions, not committed near-term release promises.

---

# What is deliberately not on this roadmap

The following do not justify roadmap entries by themselves:

- file-size reduction;
- arbitrary refactoring quotas;
- release-number milestones with no user/runtime outcome;
- adding another execution backend because an existing module is large;
- broad feature expansion that bypasses unresolved execution truth;
- reopening accepted WP 5.1/WP 5.2 semantics without new evidence that they are incorrect or materially unusable.

Maintainability work belongs on the roadmap only when it closes a named authority, testability, security, or product-delivery gap.

---

# Roadmap closure discipline

A roadmap item is complete when its stated outcome and evidence are satisfied. Completion should be recorded in `CHANGELOG.md` and, where it changes the current descriptive truth, in `BASELINE.md` and `ARCHITECTURE.md`.

Completed items should then be removed from this future-only roadmap rather than accumulating forever as checked boxes.
