# NodeChain Roadmap — Post-Rebaseline

**Document class:** Future work  
**Baseline date:** 2026-08-18  
**Baseline SHA:** `78f98252173eb38d4284ed92f0fd3343c5c5ce21`  
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

## Horizon 0 — CLOSED

All six Horizon 0 outcomes are sealed:

| Outcome | Implementation pin |
|---|---|
| H0.1 Research CLI authority | `f197ecbe4a9ae617ac419342676fd8a89a511f01` |
| H0.3 Singular execution authority | `989b21fe1d61332f3848474fdfd3e0d9ca1aaf5c` |
| H0.4 Singular trace authority | `b89c9dd7ba2890d4fa66f89b2b682f036446a591` |
| H0.5 Authoritative state-transition boundary | `71afaef186dca695770c73f212a7f198e97dac2b` |
| H0.2 POSIX supervised untrusted routing | `068120f6a46797182d33e100b5dadfc8ccc77b4f` |
| H0.6 Deployment profile truth | `78f98252173eb38d4284ed92f0fd3343c5c5ce21` |

The canonical deployment-profile authority is `docs/deployment-profiles.md`. Horizon 1 continues with the Workspace object model (H1.1 → H1.2 → H1.3, all sealed).

---

# Horizon 1 — Governed Research Workspace productization

**Objective:** turn the accepted research product-proof backend into a coherent user product without weakening the runtime/evidence contract.

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

## H1.6 — Workspace API and UI surfaces

H1.2 delivered the CLI operator experience and its stable machine-readable JSON contract; the API/UI product surfaces were explicitly deferred from H1.2 and are carried here.

Required properties:

- API/UI surfaces consume the H1.2 read-side JSON contract (`research open` / `runs` / `inspect` / `verify` / `compare` / `export --json`) rather than inventing a second observation path;
- surfaces remain read-only projections over the H1.1 ResearchWorkspaceSnapshot authority map — no competing execution, state, or evidence truth;
- write-path actions (run, review, recover) route through the existing governed CLI/runtime authorities, not new unsupervised entry points.

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
