# NodeChain System Specification — Implementation Mapping

**Document class:** Descriptive mapping to normative sources  
**Baseline date:** 2026-08-10  
**Baseline SHA:** `af1943c24a58d80ae048b9b9d50842cf0e0b27d1`

This document maps the current implementation to the NodeChain **System Specification** and the original **Reference Implementation** without rewriting either source to match temporary code state.

The System Specification remains normative: it defines the intended platform architecture and phased capability model. The original Reference Implementation remains the historical normative reference for the first Research & Decision Assistant. Current implementation truth is recorded in `BASELINE.md`.

---

## 1. Why this mapping exists

Two documentation errors are easy to make:

1. treating a normative design as though every described capability is already implemented; or
2. weakening the normative design whenever current code has a gap or transitional seam.

This mapping avoids both.

```text
System Specification        = intended platform semantics
Reference Implementation    = original research-chain normative reference
BASELINE.md                  = current implementation truth
ARCHITECTURE.md              = current code arrangement
ROADMAP.md                   = unresolved/future outcomes
```

---

## 2. System Specification phase mapping

The System Specification defines a ten-phase platform progression. At the current development baseline the implementation maps as follows.

| Specification phase | Baseline assessment | Current evidence class | Important remaining boundary |
|---|---|---|---|
| **1. Formal Foundation** | Mature / substantially implemented | Contracts, typed ports, envelopes, manifests, schemas, policy/invariant primitives | Continue versioning/compatibility discipline |
| **2. NodeChain Kernel** | Mature operational core | Durable Orchestrator, state, scheduling, loops/branches, review, trace, recovery, side-effect lifecycle | Singular execution/trace/state authority cleanup remains |
| **3. Harness Node SDK** | Substantial / operational | Node/package creation, manifests/contracts, validation, compatibility, packaging and trust metadata | Improve authoring/product UX rather than inventing a second node model |
| **4. Control Plane** | Substantial / operational | CLI workbench, recovery, dashboards, local API, trust/evidence/release operations | Cohesive Workspace/enterprise identity surface remains |
| **5. Execution Fabric** | Partial | Model/search/human/memory adapters; sandbox/native/supervised execution components | Complete intended adapter/fabric breadth; generic POSIX untrusted-node T3 routing is not closed |
| **6. Memory & Validation** | Substantial | Governed memory mechanisms, schema/semantic validation, confidence/claim validation surfaces | Enterprise data/tenant controls and product integration remain |
| **7. Reference Autonomous Chains** | Partial but proven across multiple domains | Research & Decision Assistant; Code Review; post-v3.6 Research Workspace proof substrate | Full reference-product family and product UX remain |
| **8. Registry & Evaluation** | Split: registry substantial; evaluation substantial | Local/certified/remote registry mechanics; suites/scorecards/signing/certification | Evaluation is not yet universally bound to complete governed-runtime execution |
| **9. Builder Experience** | Partial | Rich CLI, dashboards, blueprint tooling, local API, composition primitives | Governed Workspace and Blueprint Studio are not yet cohesive products |
| **10. Visual Builder & Ecosystem** | Future | Foundational node/registry/blueprint mechanics exist | Visual composition, managed ecosystem and broad third-party distribution remain |

This table is descriptive. It does not redefine the phases or their normative intent.

---

## 3. Reference Implementation status

The original Reference Implementation defines the Research & Decision Assistant as the first concrete autonomous system and establishes important design expectations around:

- twelve Harness Nodes;
- research-goal interpretation and planning;
- academic search;
- source ingestion and quality evaluation;
- evidence synthesis and claim validation;
- risk/confidence classification;
- cited response generation;
- governed memory write decisions;
- complete trace collection;
- bounded source-quality looping;
- human review for high-risk output;
- typed contracts and policy-controlled execution.

Those concepts remain architecturally important and the general `research_decision_v1.yaml` chain still reflects that lineage.

The Reference Implementation should now be classified as:

> **Historical normative reference — Research & Decision Assistant v1**

It should not be used as an inventory of everything currently implemented in NodeChain.

---

## 4. What has advanced beyond the original Reference Implementation

The current repository contains major platform capabilities that were later-stage or outside the first reference implementation, including:

- package/registry trust and remote distribution mechanics;
- lockfiles, certification, evaluation and assurance artifacts;
- extensive operator/recovery surfaces;
- multi-step side-effect lifecycle and unknown-state recovery;
- operator-authorized retry execution with lineage/capsules/fencing;
- native/supervised execution hardening;
- Code Review domain chains and governed patch/test patterns;
- local API and richer dashboard surfaces;
- public hosted CI/release governance;
- `ResearchWorkspaceBundleV1` and the governed Research Workspace product-proof path.

These advances should be described by current baseline/architecture documents rather than backfilled into the original reference document.

---

## 5. What remains aligned with the original gaps

Several original limitations remain strategically relevant even though the platform has advanced substantially:

- multi-tenant isolation is not yet a general product capability;
- high-volume concurrent service execution has not been established as an enterprise SLO-qualified platform;
- a visual builder is not yet the primary product surface;
- broad hosted/managed execution is not available;
- sensitive trace/evidence governance requires deployment/product-level policy beyond simply having a trace subsystem.

These are carried into the post-rebaseline roadmap as enterprise/product outcomes rather than treated as defects in the historical reference design.

---

## 6. The Research Workspace is a new reference-product proof, not a rewrite of the original chain

The post-v3.6 Governed Research Workspace intentionally differs from the original twelve-node chain.

It uses a sealed fixture corpus and an eleven-node execution path with `qualified_source_linker` before synthesis:

```text
goal_interpreter
→ task_planner
→ context_selector
→ fixture search_tool
→ source_ingestion
→ source_quality_evaluator
→ qualified_source_linker
→ evidence_synthesizer
→ claim_validator
→ risk_classifier
→ response_generator
```

It then finalizes a `ResearchWorkspaceBundleV1` containing integrity-bound research artifacts.

Its purpose is to prove a product/evidence contract:

- deterministic source substrate;
- provenance/hash continuity;
- guarded external-call semantics;
- fault truth derived from runtime evidence;
- durable review/resume;
- verifiable terminal bundle.

The general Research & Decision Assistant and the Governed Research Workspace should therefore remain separate documented profiles rather than being forced into one misleading diagram.

---

## 7. Normative concepts that remain load-bearing

Across both old and new product paths, the following System Specification / Reference Implementation ideas remain central:

### Contracted nodes

Node behavior is constrained by explicit entry/exit and capability contracts rather than informal graph conventions.

### Typed composition

Connections carry semantic meaning and compatibility expectations.

### Policy-controlled execution

Permissions should be enforced before the governed operation, not inferred from a post-run audit.

### Trace truth

Execution evidence must reflect actual attempts, failures, retries/recovery, review, and final outcomes.

### Bounded autonomy

Loops, costs, retries, review, and external actions require explicit limits/authority.

### Provenance and evidence

Source attribution and evidence identity cannot be fabricated by downstream synthesis.

### Human authority

High-risk or uncertain paths can require durable human decisions rather than relying on model self-approval.

### Reuse with governance intact

A reusable node remains subject to trust, policy, side-effect, trace, validation, and evaluation constraints wherever it is composed.

---

## 8. Areas where current code is intentionally below the normative end state

The current implementation still has several authority seams documented in `BASELINE.md` and `ARCHITECTURE.md`:

- the lightweight `chain_orchestrator.py` can directly execute a node outside the full orchestrator;
- not every runtime trace write has been consolidated through one durable emitter path;
- authoritative state transitions are not yet expressed through one explicit transition coordinator;
- generic POSIX untrusted Harness Node execution remains fail-closed pending T3 supervised routing;
- evaluation can run structurally or through direct-node quality paths rather than always through the complete governed runtime;
- multi-tenant/managed service controls remain future work.

These are implementation gaps relative to the broader architecture. They do not justify weakening the normative model.

---

## 9. How future documentation should use the specification

When a new feature is proposed:

1. identify which normative layer/phase it belongs to;
2. verify whether current primitives already satisfy part of the requirement;
3. avoid creating a parallel substrate if the existing governed runtime can own the behavior;
4. define the runtime/evidence boundary that proves the requirement;
5. update `BASELINE.md` only after the code changes;
6. remove completed work from `ROADMAP.md` after acceptance;
7. do not edit the System Specification merely to make the current implementation appear complete.

The specification is useful precisely because it remains a stable target while the implementation evolves toward it.
