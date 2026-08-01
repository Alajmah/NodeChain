# NodeChain Reference Implementation
## Research and Decision Assistant
### Autonomous Chain — Phase 1 Reference System
**Version 1.0 · NodeChain Platform**

---

> **Document Purpose**
> This document defines the first production-grade Autonomous Chain built on the NodeChain platform.
> It serves as the architectural stress test, implementation guide, and living reference for the platform.
> Every platform primitive is exercised by this chain. Nothing here is a toy or a placeholder.

---

## Table of Contents

1. [Purpose and Design Intent](#1-purpose-and-design-intent)
2. [Chain Overview](#2-chain-overview)
3. [Node Specifications](#3-node-specifications)
4. [Runtime Execution Design](#4-runtime-execution-design)
5. [Memory Write Flow](#5-memory-write-flow)
6. [Trace Schema](#6-trace-schema)
7. [Search Source Architecture](#7-search-source-architecture)
8. [Implementation Decisions](#8-implementation-decisions)
9. [Build Sequence](#9-build-sequence)
10. [Open Questions and Known Gaps](#10-open-questions-and-known-gaps)

---

## 1. Purpose and Design Intent

This document defines the Research and Decision Assistant — the first real Autonomous Chain built on the NodeChain platform. It is not a tutorial or a demonstration. It is the reference system that pressure-tests every platform primitive simultaneously.

### 1.1 Why This Chain

A reference implementation must be serious enough to reveal architectural weaknesses. The Research and Decision Assistant was chosen because it exercises the full breadth of NodeChain's claims:

| Capability | How It Is Exercised |
|---|---|
| Planning | Task Planner Node decomposes a complex goal into ordered subtasks with dependencies |
| Tool use | Search Tool Node calls academic APIs through protocol adapters and invocation envelopes |
| Context control | Context Selector Node governs what each downstream node is permitted to see |
| Validation | Source Quality Evaluator and Claim Validator run independent validation passes |
| Memory | Memory Write Decision Node proposes, evaluates, and conditionally commits durable memory |
| Traceability | Every node invocation, contract decision, and policy decision produces a trace event |
| Risk scoring | Risk / Confidence Classifier assigns structured uncertainty to the final output |
| Multi-step execution | Twelve nodes execute in a governed sequence with branching and retry paths |
| Looping | Evidence synthesis may loop back to search if source quality is insufficient |
| Node contracts | All nodes declare typed entry and exit contracts enforced by the runtime |
| Protocol adapters | Five academic search APIs run through separate adapters, same invocation envelope |

### 1.2 What This Document Covers

- The complete node-by-node specification for this chain
- Node contracts for every node including entry contract, exit contract, permissions, and side effects
- The runtime execution sequence and lifecycle
- The loop architecture and retry paths
- The memory write flow end to end
- The trace schema for this chain
- The human review gate design
- The search source architecture — five academic APIs with domain routing
- Implementation decisions including technology choices and rationale
- The build sequence for solo implementation with AI assistance

### 1.3 What This Document Does Not Cover

- The full NodeChain platform specification — see the NodeChain System Specification
- Visual builder tooling — not required for this implementation
- Public registry — not required for this implementation
- Evaluation framework — evaluation hooks are included but the evaluation runner is a later phase

---

## 2. Chain Overview

### 2.1 Goal Statement

> Given a complex research question, produce a cited recommendation from peer-reviewed academic sources, validate sources and claims, track uncertainty, and decide whether memory should be updated.

### 2.2 Chain Identity

| Field | Value |
|---|---|
| chain_id | nodechain.reference.research-decision.v1 |
| name | Research and Decision Assistant |
| version | 1.0.0 |
| chain_type | research_chain / decision-support_chain |
| owner | NodeChain Platform |
| runtime_target | NodeChain Kernel v1 |
| deployment_profile | local / containerized |
| trace_policy | full_trace_required |
| memory_policy | governed_write_with_approval |
| review_policy | human_review_on_high_risk |
| loop_policy | max_2_iterations_with_escalation |

### 2.3 Node Graph

The chain executes through twelve nodes. The primary path is linear. Two loop-back paths exist. One human review gate may interrupt execution. One memory write flow runs at the end.

```
Primary Execution Path
──────────────────────────────────────────────────────────────
 1.  Goal Interpreter Node
 2.  Task Planner Node
 3.  Context Selector Node
 4.  Search Tool Node          ← loops back to 3 if source quality fails
 5.  Source Ingestion Node
 6.  Source Quality Evaluator  ← triggers loop if quality insufficient
 7.  Evidence Synthesizer Node
 8.  Claim Validator Node
 9.  Risk / Confidence Classifier  ← triggers human review if risk HIGH
10.  Response Generator Node
11.  Memory Write Decision Node
12.  Trace Collector Node
──────────────────────────────────────────────────────────────

Loop Path (max 2 iterations)
  Source Quality Evaluator → Context Selector → Search Tool →
  Source Ingestion → Source Quality Evaluator

Review Path (conditional)
  Risk Classifier → Human Review Gate → Response Generator
```

### 2.4 Chain Invariants

These invariants must hold throughout every execution. The runtime is responsible for enforcing them.

- All twelve nodes must exist and be resolvable before chain execution begins
- All node contracts must pass compatibility checks at load time, not at runtime
- All connections between nodes must satisfy semantic type and schema compatibility
- All loops must be bounded — maximum two iterations before escalation
- All external side effects must be declared in the node manifest before invocation
- The human review gate must produce a trace event regardless of outcome
- Memory writes must follow the full write approval flow — no silent commits
- The final trace must include every material decision made during execution

---

## 3. Node Specifications

Each node is specified with its identity, capability, entry contract, exit contract, permissions, side effects, and trace requirements. These specifications are the authoritative source for implementation. The runtime enforces them.

---

### 3.1 Goal Interpreter Node

| Field | Value |
|---|---|
| node_id | nodechain.research.goal-interpreter.v1 |
| node_type | Intent Node |
| capability | Parses and normalizes a raw user query into a structured research goal with constraints, scope, and success criteria |
| implementation | Model-backed — single model call with structured output schema |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  RawUserQuery
required_fields:      query (string, max 2000 chars)
optional_fields:      preferred_sources, time_constraint, depth_preference, output_format
allowed_context:      current_request only
allowed_memory:       none
allowed_tools:        none
max_tokens:           2000
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: NormalizedResearchGoal
required_fields:      goal_statement, research_scope, success_criteria,
                      constraints, uncertainty_markers
optional_fields:      preferred_source_types, time_sensitivity, depth_level
side_effects:         none
must_not_include:     executed_action, tool_result, external_data
validation:           schema_required, semantic_required
```

---

### 3.2 Task Planner Node

| Field | Value |
|---|---|
| node_id | nodechain.research.task-planner.v1 |
| node_type | Planner Node |
| capability | Decomposes a normalized research goal into an ordered task plan with dependencies, search strategies, source routing, and validation checkpoints |
| implementation | Model-backed — chain-of-thought reasoning with structured output |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  NormalizedResearchGoal
required_fields:      goal_statement, research_scope, success_criteria, constraints
allowed_context:      current_request, normalized_goal
allowed_memory:       none
allowed_tools:        none
max_tokens:           4000
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: TaskPlan
required_fields:      tasks[], dependencies[], search_queries[],
                      source_routing, validation_checkpoints[],
                      assumptions[], risk_level
source_routing:       primary[], secondary[], domain_specific{}
optional_fields:      fallback_strategies, time_estimate
side_effects:         none
must_not_include:     executed_action, tool_result, fetched_content
validation:           schema_required, semantic_required, policy_required
```

---

### 3.3 Context Selector Node

| Field | Value |
|---|---|
| node_id | nodechain.research.context-selector.v1 |
| node_type | Context Selector Node |
| capability | Determines which context, memory, and tool access is permitted for each downstream node based on the task plan and runtime policy. Grants specific academic API adapter permissions based on domain routing. |
| implementation | Deterministic rules engine — no model call |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  TaskPlan
required_fields:      tasks[], risk_level, source_routing
allowed_context:      task_plan, runtime_policy
allowed_memory:       read_policy_memory only
allowed_tools:        none
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: ContextBundle
required_fields:      per_node_context_grants[], per_node_tool_grants[],
                      per_node_memory_grants[], per_node_adapter_grants[],
                      policy_decisions[]
adapter_grants:       scoped per source_routing — only granted adapters may be called
side_effects:         none
must_not_include:     actual_content_data, credentials, raw_memory
validation:           policy_required, permission_required
```

---

### 3.4 Search Tool Node

| Field | Value |
|---|---|
| node_id | nodechain.research.search-tool.v1 |
| node_type | Tool Node / API Adapter Node |
| capability | Executes search queries against granted academic source APIs through protocol adapters. Routes queries by domain. Returns raw structured results from each source. |
| implementation | Multi-source adapter — five academic API adapters with domain router |
| side_effects | external_read (per granted adapter) |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  ToolCallProposal
required_fields:      search_queries[], adapter_grants[] (from ContextBundle)
allowed_context:      approved_search_queries, adapter_grants only
allowed_memory:       none
allowed_tools:        granted adapters only — no others
allowed_credentials:  none — all APIs are open access
max_results_per_query: 10 per source
network_policy:       allowlist only — api.semanticscholar.org,
                      export.arxiv.org, api.openalex.org,
                      api.crossref.org, eutils.ncbi.nlm.nih.gov
risk_constraints:     external_read_only, no_write, no_mutation
```

**Exit Contract**
```
semantic_output_type: RawSearchResults
required_fields:      results[], query_reference, adapters_used[],
                      result_count_per_source{}, latency_ms_per_source{}
per_result_fields:    source_id, origin_api, title, authors[],
                      doi, abstract_snippet, publication_date,
                      peer_reviewed, citation_count, venue,
                      open_access, pdf_url, retrieval_timestamp
side_effects:         external_read — declared and traced per adapter
must_not_include:     results_from_non_granted_adapters, credential_data
validation:           schema_required, side_effect_validation_required
```

**Adapter Rate Limits** (enforced by each adapter, transparent to envelope)

| Adapter | Endpoint | Rate Limit | API Key |
|---|---|---|---|
| Semantic Scholar | api.semanticscholar.org/graph/v1 | 1 req/s (free), 10 req/s (key) | Optional — free |
| arXiv | export.arxiv.org/api/query | 3 req/s | None required |
| OpenAlex | api.openalex.org | 10 req/s (polite pool) | None — email header |
| CrossRef | api.crossref.org | Polite pool | None — User-Agent header |
| PubMed | eutils.ncbi.nlm.nih.gov | 3 req/s (free), 10 req/s (key) | Optional — free |

---

### 3.5 Source Ingestion Node

| Field | Value |
|---|---|
| node_id | nodechain.research.source-ingestion.v1 |
| node_type | Data Transformer Node |
| capability | Normalizes raw results from all academic APIs into a unified SourceRecord schema. Preserves origin-specific credibility signals without flattening them. |
| implementation | Deterministic function — no model call, no external API |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  RawSearchResults
required_fields:      results[], query_reference, adapters_used[]
allowed_context:      raw_search_results only
allowed_memory:       none
allowed_tools:        none
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: SourceSet
required_fields:      sources[], ingestion_timestamp, query_reference
per_source_fields:
  source_id           — generated UUID
  origin_api          — which adapter produced this result
  title
  authors[]
  publication_date
  doi
  abstract
  source_type         — journal_article | preprint | conference | review
  peer_reviewed       — bool
  citation_count
  venue
  subject_areas[]
  open_access         — bool
  pdf_url             — if available
  credibility_signals — origin-specific structured signals preserved
  provenance          — adapter, query, retrieval_timestamp
side_effects:         none
validation:           schema_required
```

**Credibility Signals by Origin**

| Origin | Preserved Signals |
|---|---|
| Semantic Scholar | citation_count, influential_citation_count, author_h_index |
| arXiv | subject_classification, version_count, comment_field |
| OpenAlex | concept_scores[], cited_by_count, institution_affiliations[] |
| CrossRef | publisher, funder[], license_type, reference_count |
| PubMed | mesh_terms[], publication_types[], clinical_trial_id |

---

### 3.6 Source Quality Evaluator Node

| Field | Value |
|---|---|
| node_id | nodechain.research.source-quality-evaluator.v1 |
| node_type | Validator Node |
| capability | Evaluates each source using structured credibility signals from the SourceRecord. Scores credibility, recency, relevance, and bias. Produces a set-level quality decision. May trigger loop-back with revised search strategy. |
| implementation | Model-backed — structured evaluation with scoring rubric against real credibility signals |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  SourceSet
required_fields:      sources[], query_reference
allowed_context:      source_set, research_goal
allowed_memory:       none
allowed_tools:        none
max_tokens:           6000
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: QualifiedSourceSet
required_fields:      sources_with_scores[], set_quality_decision,
                      quality_summary, loop_required (bool),
                      revised_search_strategy (if loop_required=true)
set_quality_decision: pass | insufficient | fail
per_source_score:
  source_id
  credibility_score   — weighted from peer_review, citation_count, venue
  recency_score       — based on publication_date vs query time_sensitivity
  relevance_score     — semantic match to research goal
  bias_indicators[]
  overall_score
  include_in_synthesis — bool
loop_trigger:         loop_required=true → Context Selector with revised_search_strategy
validation:           schema_required, semantic_required
```

---

### 3.7 Evidence Synthesizer Node

| Field | Value |
|---|---|
| node_id | nodechain.research.evidence-synthesizer.v1 |
| node_type | Reasoning Node |
| capability | Synthesizes qualified sources into a structured evidence base with claim extraction, source attribution, confidence weighting, and contradiction identification. All claims must be traceable to source_ids. |
| implementation | Model-backed — deep reasoning with citation enforcement |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  QualifiedSourceSet
required_fields:      sources_with_scores[], research_goal, loop_count
allowed_context:      qualified_source_set, normalized_goal, task_plan
allowed_memory:       read_session_memory only
allowed_tools:        none
max_tokens:           12000
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: EvidenceBase
required_fields:      claims[], contradictions[], evidence_gaps[],
                      source_map[], confidence_summary, synthesis_notes
per_claim_fields:
  claim_id
  statement
  supporting_sources[]  — must reference real source_ids from SourceSet
  confidence_level
  uncertainty_markers[]
side_effects:         none
must_not_include:     unsupported_assertions, fabricated_citations,
                      claims_without_source_ids
validation:           schema_required, semantic_required,
                      factuality_validation_required
```

---

### 3.8 Claim Validator Node

| Field | Value |
|---|---|
| node_id | nodechain.research.claim-validator.v1 |
| node_type | Validator Node |
| capability | Validates each claim through two independent passes. Pass 1 — structural/schema validation (deterministic). Pass 2 — factual consistency validation against source content (model-backed). Results are kept separate. |
| implementation | Hybrid — deterministic pass first, model-backed consistency check second |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  EvidenceBase
required_fields:      claims[], source_map[]
allowed_context:      evidence_base, qualified_source_set
allowed_memory:       none
allowed_tools:        none
validation_passes:    [structural_validation, consistency_validation]
                      executed in sequence, results never merged
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: ValidatedEvidenceBase
required_fields:      validated_claims[], rejected_claims[],
                      validation_summary, structural_pass_result,
                      consistency_pass_result
per_validated_claim:
  claim_id
  structural_status   — pass | fail | warning
  consistency_status  — pass | fail | uncertain
  overall_status
  validation_notes[]
critical_rule:        structural and consistency results are separate fields — never merged
side_effects:         none
validation:           schema_required, policy_required
```

---

### 3.9 Risk / Confidence Classifier Node

| Field | Value |
|---|---|
| node_id | nodechain.research.risk-classifier.v1 |
| node_type | Risk Classifier Node |
| capability | Assigns structured risk and confidence scores to the validated evidence base. Determines whether human review is required before response generation. |
| implementation | Hybrid — rule-based risk thresholds with model-backed confidence estimation |
| side_effects | none — human_review_request is a port output, not a side effect |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  ValidatedEvidenceBase
required_fields:      validated_claims[], rejected_claims[], validation_summary
allowed_context:      validated_evidence, task_plan, chain_policy
allowed_memory:       none
allowed_tools:        none
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: RiskAssessment
required_fields:      overall_confidence (0.0–1.0), overall_risk_level,
                      per_claim_confidence[], uncertainty_summary,
                      review_required (bool), review_reason
overall_risk_level:   LOW | MEDIUM | HIGH
routing:              review_required=true  → Human Review Node
                      review_required=false → Response Generator directly
side_effects:         none
validation:           schema_required, policy_required
```

---

### 3.10 Response Generator Node

| Field | Value |
|---|---|
| node_id | nodechain.research.response-generator.v1 |
| node_type | Reasoning Node |
| capability | Produces the final cited recommendation from validated evidence, risk assessment, and optional human review decision. Formats citations using DOIs and source metadata. Enforces uncertainty disclosure. |
| implementation | Model-backed — structured response generation with citation enforcement |
| side_effects | none |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  ValidatedEvidenceBase + RiskAssessment
                      [+ HumanApprovalDecision if review occurred]
required_fields:      validated_claims[], risk_assessment, original_goal
optional_fields:      human_review_decision, human_review_notes
allowed_context:      validated_evidence, risk_assessment,
                      normalized_goal, human_decision (if present)
allowed_memory:       read_session_memory only
max_tokens:           8000
risk_constraints:     no_external_side_effects
```

**Exit Contract**
```
semantic_output_type: FinalResponse
required_fields:      recommendation, cited_claims[], confidence_statement,
                      uncertainty_disclosures[], source_list[],
                      response_metadata
source_list_fields:   source_id, doi, title, authors[], venue,
                      publication_date, url
response_metadata:    model_used, generation_timestamp, loop_count,
                      review_occurred, overall_confidence
must_not_include:     uncited_factual_claims, fabricated_sources,
                      suppressed_uncertainty
validation:           schema_required, semantic_required, policy_required
```

---

### 3.11 Memory Write Decision Node

| Field | Value |
|---|---|
| node_id | nodechain.research.memory-write-decision.v1 |
| node_type | Memory Writer Node |
| capability | Evaluates whether the research output merits durable memory storage. Proposes write candidates. Runs policy and validation. Commits approved writes. Never writes silently. |
| implementation | Model-backed evaluation + deterministic write flow |
| side_effects | memory_write (conditional — only if policy approves) |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  FinalResponse + RiskAssessment
required_fields:      recommendation, cited_claims[], confidence_statement,
                      overall_confidence, overall_risk_level
allowed_context:      final_response, risk_assessment, memory_policy
allowed_memory:       read_user_memory (deduplication check only),
                      write_candidate_memory (pending approval)
allowed_tools:        none
risk_constraints:     memory_write_requires_policy_approval
```

**Exit Contract**
```
semantic_output_type: MemoryWriteDecision
required_fields:      write_decision, write_candidates[] (if write),
                      policy_decision, validation_result,
                      write_result (if committed)
write_decision:       write | skip | defer
write_candidate_fields:
  memory_id           — UUID
  scope               — task_memory (v1)
  subject
  content             — recommendation or key findings, not raw model output
  confidence          — must exceed 0.7 to be write-eligible
  sensitivity         — LOW | MEDIUM | HIGH
  retention_policy    — set by policy, not by node
  provenance          — chain_id, run_id, source_ids[], timestamp
side_effects:         memory_write — declared, policy-approved, traced
must_not_include:     silent_write, unapproved_write,
                      write_of_rejected_claims
validation:           schema_required, memory_validation_required,
                      policy_required
```

---

### 3.12 Trace Collector Node

| Field | Value |
|---|---|
| node_id | nodechain.research.trace-collector.v1 |
| node_type | Trace Node |
| capability | Assembles the complete Chain Trace from all node invocation records, contract decisions, policy decisions, validation results, and memory events. Writes the trace to configured sink. Produces the final audit record. |
| implementation | Deterministic — no model call, no external API |
| side_effects | file_write (trace output to configured sink) |
| trust_level | verified |

**Entry Contract**
```
semantic_input_type:  ChainRunState
required_fields:      all node invocation records, all contract decisions,
                      all policy decisions, all validation results,
                      all memory events, final_response reference
allowed_context:      full chain state
allowed_memory:       read_trace_memory only
allowed_tools:        none
side_effect_declaration: file_write to trace sink — declared and expected
```

**Exit Contract**
```
semantic_output_type: ChainTrace
required_fields:      trace_id, chain_id, run_id, start_time, end_time,
                      node_invocations[], contract_decisions[],
                      policy_decisions[], validation_results[],
                      memory_events[], final_outcome,
                      total_cost_usd, total_latency_ms
side_effects:         file_write — declared
truth_rule:           must not claim a step occurred unless actually executed
validation:           schema_required, completeness_required
```

---

## 4. Runtime Execution Design

### 4.1 Execution Lifecycle

Every step is traced. No step is skipped.

| Step | Action | Trace Event |
|---|---|---|
| 1 | Receive research query | chain_started |
| 2 | Create chain run — assign run_id | chain_run_created |
| 3 | Load chain blueprint and resolve all nodes | blueprint_loaded |
| 4 | Validate all node contracts at load time | contracts_validated |
| 5 | Validate all typed port connections | ports_validated |
| 6 | Initialize Chain State | state_initialized |
| 7 | Compile Invocation Envelope for Goal Interpreter | envelope_compiled |
| 8 | Apply Harness Control Plane decisions | control_plane_applied |
| 9 | Invoke node — execute — validate output | node_invoked / node_succeeded |
| 10 | Record trace event — update Chain State | trace_recorded / state_updated |
| 11 | Determine next transition | transition_evaluated |
| 12 | Continue, branch, loop, pause, or escalate | routing_decision |
| 13 | Validate final response | final_validation |
| 14 | Emit complete Chain Trace | chain_completed |
| 15 | Run evaluation hooks | evaluation_triggered |
| 16 | Apply approved memory writes | memory_committed |

### 4.2 Loop Architecture

This chain contains one defined loop. It is bounded. No unbounded loop is valid.

```
Loop: Source Quality Insufficient
─────────────────────────────────────────────────────────────
loop_id:           research.source-quality-loop
entry_condition:   Source Quality Evaluator returns loop_required=true
exit_condition:    Source Quality Evaluator returns loop_required=false
max_iterations:    2
escalation:        After 2 iterations → pause chain → request human review
loop_path:         Source Quality Evaluator → Context Selector (revised queries)
                   → Search Tool → Source Ingestion → Source Quality Evaluator
trace_required:    loop_entered, loop_exited (or escalation_triggered)
─────────────────────────────────────────────────────────────
```

### 4.3 Human Review Gate

The human review gate is real. It pauses chain execution. It requires an actual decision. CLI-based in the first implementation.

```
Human Review Gate: High Risk Output
─────────────────────────────────────────────────────────────
trigger:            Risk Classifier returns review_required=true
review_payload:     validated_claims[], risk_assessment,
                    confidence_summary, uncertainty_disclosures[]
allowed_decisions:  approve | reject | request_revision
timeout:            30 minutes → escalates to chain_failed
escalation_path:    chain_failed with reason=review_timeout
approver_role:      chain_operator
approve:            Response Generator proceeds with human_review_decision=approved
reject:             Chain terminates with status=rejected_by_reviewer
request_revision:   Task Planner Node re-invoked with revision instructions
trace_required:     human_review_requested, human_review_completed (or timeout)
─────────────────────────────────────────────────────────────
```

### 4.4 Failure Handling

| Failure Type | Handling Strategy |
|---|---|
| Node schema validation failure | Retry same node once with reduced context. Fail chain on second failure. |
| Model call failure (timeout) | Retry with same model, extended timeout. Then retry with fallback model. |
| Academic API unavailable | Retry with remaining granted adapters. Trace adapter_fallback event. |
| All adapters unavailable | Pause chain. Emit escalation_triggered. Wait for operator. |
| Source quality loop exhausted | Pause chain. Request human review with reason=source_quality_exhausted. |
| Claim validation failure (all claims) | Route to Task Planner for revised research strategy. Max one revision. |
| Risk classifier returns HIGH + no reviewer | Pause chain. Emit escalation_triggered trace. Wait for operator. |
| Memory write policy rejection | write_decision=skip. Trace policy_rejection. Continue to Trace Collector. |
| Trace write failure | Attempt alternate sink (stderr). Flag chain as trace_incomplete. Never silent. |

---

## 5. Memory Write Flow

The memory write flow is the first full implementation of NodeChain's governed memory model. It must be real — not stubbed — from the first implementation. The flow has five mandatory stages.

```
Stage 1 — Proposal
  Memory Write Decision Node evaluates FinalResponse
  and proposes MemoryWriteCandidate(s)

Stage 2 — Policy
  Memory policy evaluates each candidate for
  scope, sensitivity, and permission

Stage 3 — Validation
  Validator checks correctness, confidence threshold (≥ 0.7),
  source attribution, and deduplication

Stage 4 — Commit
  Runtime commits approved writes to ChromaDB
  with full provenance metadata

Stage 5 — Trace
  Trace Collector records decision, candidate,
  policy result, and write reference
```

### 5.1 Write Candidate Schema

| Field | Description |
|---|---|
| memory_id | Generated UUID — unique per candidate |
| scope | task_memory — scoped to this chain run in v1 |
| subject | Normalized subject extracted from research goal |
| content | Recommendation or key findings — not raw model output |
| confidence | Numeric from Risk Classifier — must exceed 0.7 |
| sensitivity | LOW / MEDIUM / HIGH — from content classification |
| retention_policy | session / 7d / 30d / permanent — set by policy, not node |
| provenance | chain_id, run_id, source_ids[], generation_timestamp |
| owner | chain_operator |

### 5.2 Write Guard Rules

These rules are enforced by the runtime. They cannot be bypassed by a node.

- Writes based on rejected claims are blocked — no exceptions
- Writes with confidence below 0.7 are blocked — configurable threshold
- Writes of HIGH sensitivity content require explicit policy permission
- Duplicate detection runs before commit — same subject and content within 24 hours is skipped
- Every blocked write produces a trace event with reason codes
- No write occurs without a corresponding trace event

---

## 6. Trace Schema

Every material decision in this chain produces a trace event. The trace is the authoritative execution record.

### 6.1 Trace Event Fields

| Field | Description |
|---|---|
| trace_id | Chain-level trace identifier — UUID |
| event_id | Per-event identifier — UUID |
| timestamp | ISO 8601 with milliseconds |
| run_id | Chain run identifier |
| chain_id | Chain definition identifier |
| node_id | Node that produced this event |
| step_id | Step within the chain run |
| contract_id | Contract applied at this step |
| policy_id | Policy applied at this step (if any) |
| event_type | One of the defined event types |
| actor | node / runtime / human / policy_engine |
| input_reference | Hash or reference to input |
| output_reference | Hash or reference to output |
| decision | The decision made at this event |
| reason_codes | Machine-readable reason codes array |
| cost_usd | Cost incurred at this step |
| latency_ms | Latency at this step |
| risk_level | Risk level at this step |
| metadata | Extensible key-value metadata |

### 6.2 Required Trace Events for This Chain

These events must appear in every complete chain trace. Missing events indicate an incomplete trace — a platform error, not a node error.

- `chain_started` — once, at chain initialization
- `node_invoked` — once per node per attempt
- `node_succeeded` or `node_failed` — once per node per attempt
- `contract_validated` — once per node, at load time
- `policy_evaluated` — for every policy decision
- `tool_called` and `tool_result_received` — for every adapter invocation, per source
- `validation_started`, `validation_passed` or `validation_failed` — for every validation pass
- `loop_entered` and `loop_exited` — if the source quality loop activates
- `human_review_requested` and `human_review_completed` — if review gate activates
- `memory_write_requested`, `memory_write_allowed` or `memory_write_blocked` — per candidate
- `chain_completed` or `chain_failed` — once, at termination

### 6.3 Trace Truth Rule

> The trace must not claim a step occurred unless it was actually executed.
> Planned steps that were skipped must be recorded as skipped — not omitted.
> Simulated steps must be marked as simulated — not recorded as executed.
> Partial execution must be recorded as partial — not as complete.

This rule is enforced by the Trace Collector Node and validated at chain completion.

---

## 7. Search Source Architecture

### 7.1 Source Overview

All five sources are free, open, and require no paid API keys for basic access. Semantic Scholar and PubMed offer free optional keys that increase rate limits. Register for both before building.

| Source | Endpoint | Purpose | Key Required |
|---|---|---|---|
| Semantic Scholar | api.semanticscholar.org/graph/v1 | Primary search and citation exploration | Optional (free) |
| arXiv | export.arxiv.org/api/query | Pre-print papers — math, physics, CS | None |
| OpenAlex | api.openalex.org | Open scholarly metadata and citation graphs | None (email header) |
| CrossRef | api.crossref.org | DOI-based metadata retrieval | None (User-Agent header) |
| PubMed | eutils.ncbi.nlm.nih.gov | Biomedical and life sciences literature | Optional (free) |

### 7.2 Domain Routing

The Task Planner Node outputs a `source_routing` field that the Context Selector uses to grant adapter permissions.

```yaml
source_routing:
  primary:
    - semantic_scholar
    - openalex
  secondary:
    - crossref
  domain_specific:
    biomedical:
      - pubmed
    preprint_heavy:
      - arxiv
    citation_exploration:
      - semantic_scholar
      - openalex
```

Only granted adapters may be called. The invocation envelope enforces this. An ungrated adapter call is a contract violation.

### 7.3 Adapter Directory Structure

```
adapters/
├── model_adapter.py       — Ollama / Anthropic model adapter
├── search/
│   ├── base.py            — BaseSearchAdapter interface
│   ├── semantic_scholar.py
│   ├── arxiv.py
│   ├── openalex.py
│   ├── crossref.py
│   └── pubmed.py
├── chroma_adapter.py      — Local document store and memory store
└── human_adapter.py       — CLI review gate
```

### 7.4 Credibility Signals Preserved Per Source

| Source | Preserved Signals |
|---|---|
| Semantic Scholar | citation_count, influential_citation_count, author_h_index |
| arXiv | subject_classification, version_count, comment_field |
| OpenAlex | concept_scores[], cited_by_count, institution_affiliations[] |
| CrossRef | publisher, funder[], license_type, reference_count |
| PubMed | mesh_terms[], publication_types[], clinical_trial_id |

### 7.5 Rate Limit Handling

Rate limits are adapter responsibility. The invocation envelope does not need to know about them. Each adapter implements:

- Tenacity retry with exponential backoff
- Per-source request rate tracking
- Polite headers where required (User-Agent, email for OpenAlex)
- Graceful degradation — if one source fails, others continue
- Trace event per adapter failure with reason code

---

## 8. Implementation Decisions

### 8.1 Execution Environment

| Decision | Rationale |
|---|---|
| Python 3.11+ | AI ecosystem, adapter library availability, strongest AI assistance for this class of system |
| Docker Compose from day one | NodeChain's isolation principles must be lived in the reference implementation, not added retroactively |
| Fully local — no external model API | Complete offline operation. No cost per query. No rate limits interrupting build cycles. Privacy preserved. |
| Local first, cloud-ready | Container design ensures cloud deployment without re-architecture when needed |

### 8.2 Model Layer

| Decision | Rationale |
|---|---|
| Ollama — local model server | Runs LLaMA 3, Qwen 2.5, Mistral, and others locally. Clean API. No credentials. No usage cost. |
| Model-agnostic adapter layer | Agnosticism is a platform requirement. The adapter sits behind the invocation envelope. |
| Qwen 2.5 72B or LLaMA 3 70B — default | Strongest local models currently available for reasoning-heavy tasks. Require 40GB+ RAM with quantization. |
| Smaller model fallback (13B) | For machines with 16GB RAM. Capability reduction is real but workable for development. |
| Model selection per node type | Reasoning nodes and validator nodes may use different models based on capability and cost profile. |

**Hardware requirements by model size**

| Model Size | RAM Required | Quality Profile |
|---|---|---|
| 70B (quantized) | 40GB+ | Best — recommended for production runs |
| 13B | 16GB | Good — workable for development |
| 7B | 8GB | Limited — use only for light nodes |

### 8.3 Search Architecture

| Decision | Rationale |
|---|---|
| Five academic APIs — not generic web search | Structured credibility signals, peer review status, citation data, DOI resolution. Source quality evaluation becomes structurally honest rather than heuristic. |
| No API keys required for basic access | Fully local-compatible in terms of credentials. Optional free keys for Semantic Scholar and PubMed increase rate limits. |
| Domain routing from Task Planner | The research domain determines which sources are relevant. Granting all adapters always wastes rate limit budget and degrades result quality. |
| All adapters behind same invocation envelope | This is the first real test of protocol agnosticism. Five different APIs, one envelope. |

### 8.4 Memory Backing Store

| Decision | Rationale |
|---|---|
| ChromaDB — memory store | Lightweight, local, open source. Separate collection from document store. Separation enforced by contract and policy, not by separate systems. |
| Write approval flow is real — not stubbed | Memory governance is one of NodeChain's core claims. Stubbing it defeats the purpose of building a reference implementation. |
| Confidence threshold 0.7 — default | Conservative starting point. Configurable by policy. Better to write less correctly than accumulate low-confidence memory. |

### 8.5 Human Review Gate

| Decision | Rationale |
|---|---|
| Real gate — not stubbed | Pause/resume is one of the most important runtime behaviors in the spec. Designing around it now produces a runtime that cannot support it later. |
| CLI-based in v1 | A web interface adds unnecessary complexity at this stage. A CLI approval prompt is sufficient to make the gate real and runtime behavior correct. |
| 30-minute timeout with escalation | Human review that can block indefinitely is not governable. The timeout and escalation path are as important as the approval path. |

### 8.6 Validation Architecture

| Decision | Rationale |
|---|---|
| Source Quality Evaluator — model-backed | Evaluating source credibility against real signals requires judgment. Rule-based systems can only check thresholds, not interpret context. |
| Claim Validator — hybrid, two separate passes | Structural validation is deterministic and fast. Consistency validation requires model judgment. Keeping them separate makes each pass honest about what it is doing. |
| Separate trace events per pass | Merging pass results hides which validation failed and why. Separate events make failures debuggable. |

### 8.7 Trace Sink

| Decision | Rationale |
|---|---|
| Structured JSON to file — v1 | Not an observability platform yet. A well-structured local trace file following the Chain Trace schema precisely. |
| Schema compatible with database migration | The trace file format must be writable to a database without schema changes. Designing for file-only traces first produces formats that break on migration. |
| CLI trace viewer included | A trace that cannot be read during development is not a trace. Formatted CLI output makes the audit record real and usable immediately. |

---

## 9. Build Sequence

The build sequence is ordered by dependency and architectural significance. Each step must produce a committed, working state before the next begins. No step is skipped because it seems like plumbing. The plumbing is the architecture.

> **Build Principle**
> Always have something running. Not perfectly. Not completely. But running.
> Each step below must be runnable and testable before the next step begins.

### 9.1 Build Steps

1. Invocation Envelope and Node Contract schema in code — this is the runtime's law. Define before writing any node.

2. Minimal runtime loop — load blueprint, validate contracts, invoke one node, update state, emit one trace event.

3. Goal Interpreter Node — first real model call through the runtime. Validates envelope, Ollama adapter, and output schema.

4. Task Planner Node — first multi-output node with source routing. Validates task plan schema and typed port connection.

5. Context Selector Node — first deterministic node. Validates that non-model nodes work through the same invocation envelope. Validates adapter grant logic.

6. Search adapters — build BaseSearchAdapter then all five academic adapters. Test each adapter independently before wiring to the node.

7. Search Tool Node — first external side effects. Validates multi-adapter invocation, domain routing, and side-effect declaration flow.

8. Source Ingestion Node — first data transformer. Validates unified SourceRecord normalization across all five adapter schemas.

9. Source Quality Evaluator Node — first loop trigger. Validates that the runtime detects loop conditions and executes the loop path.

10. Source quality loop — first complete loop execution. Validates bounded iteration, loop trace events, and escalation path.

11. Evidence Synthesizer Node — first session memory read. Validates memory access control and governed read flow.

12. Claim Validator Node — first hybrid validator. Validates that two-pass validation produces separate trace events.

13. Risk / Confidence Classifier Node — first routing branch. Validates that the runtime correctly routes to human review or bypasses it.

14. Human review gate — first real pause and resume. Validates CLI gate, timeout, trace events, and state recovery after resume.

15. Response Generator Node — first node that consumes optional input. Validates optional port handling and DOI citation formatting.

16. Memory Write Decision Node — first governed memory write. Validates the full five-stage write flow end to end.

17. Trace Collector Node — first complete chain trace. Validates trace completeness, truth rule, and JSON output.

18. End-to-end run — full chain, real research question, complete trace output. This is the acceptance test.

### 9.2 Acceptance Criteria

The reference implementation is complete when all of the following are true in a single end-to-end run:

- A real research question produces a cited recommendation with DOI references and confidence statement
- All twelve nodes execute through the runtime with invocation envelopes
- All node contracts are validated at load time — not at invocation time
- At least two academic APIs are queried and their results normalized into unified SourceRecords
- The source quality loop executes at least once in the test run
- The human review gate activates and completes with a real operator decision
- The memory write flow runs all five stages and produces a trace event for each
- The final chain trace is a complete, auditable JSON file
- The trace viewer renders the trace in readable form on the CLI
- No step in the trace claims to have executed unless it actually executed
- The chain can be re-run from the same blueprint and produce a valid — if non-identical — trace

---

## 10. Open Questions and Known Gaps

### 10.1 Questions the Build Will Answer

- Does the contract compatibility model hold under real node composition, or do edge cases force schema relaxation?
- Is the invocation envelope expressive enough for all twelve node types, including hybrid and deterministic nodes?
- Does the domain routing logic in the Task Planner produce useful adapter grant sets, or does it need tuning against real queries?
- Does the loop architecture interact correctly with Chain State, or does state accumulate unexpectedly across iterations?
- Is the trace schema granular enough to make failures debuggable, or are additional event types needed?
- Does the CLI human review gate correctly block all downstream execution during the pause?
- Does the five-stage memory write flow introduce unacceptable latency for an interactive research chain?
- Are local model capabilities sufficient for the reasoning demands of Evidence Synthesizer and Claim Validator?

### 10.2 Known Design Tensions

**Contract strictness vs. model nondeterminism** — model outputs may vary in structure across runs. The contract model must accept valid variation without accepting invalid output. Pydantic with partial validation may be the right tool.

**Trace completeness vs. trace size** — five academic APIs each producing trace events per query, per result, per validation pass will produce large traces. Trace verbosity must be configurable by policy without sacrificing the truth rule.

**Local model capability vs. chain quality** — the research chain makes real demands on reasoning quality. If local model output quality is insufficient for claim validation or evidence synthesis, the chain will surface this honestly through confidence scores and rejected claims rather than producing confident wrong answers.

**Rate limit handling vs. chain latency** — polite rate limiting across five APIs with retries may add significant latency. The adapter layer must make this transparent to the runtime without stalling the chain.

### 10.3 What This Chain Does Not Test

- Multi-tenant isolation — this chain runs as a single operator
- High-volume concurrent execution — runtime concurrency and state isolation under load
- Node registry and packaging — nodes are locally defined in v1
- Evaluation framework — evaluation hooks are in the trace but the runner is a later phase
- Visual builder — not relevant to this phase
- GPU-accelerated model inference — Ollama CPU inference is assumed for v1

---

*NodeChain Platform · Research and Decision Assistant · Reference Implementation v1.0*
