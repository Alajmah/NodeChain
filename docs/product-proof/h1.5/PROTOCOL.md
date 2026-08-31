# H1.5 Product-Proof Protocol (FROZEN)

**Status:** FROZEN before the first scored participant. Do not edit after sessions begin.
**Study baseline (product under test):** the H1.4 seal `5d54190c87136ff217b0d2f4899d6a04ea1b486a` — the production tree (`src/`, `schemas/`, packaging) must be byte-identical to that seal for every scored session; the scenario generator enforces this by exact diff, not ancestry.
**Governing invariant:** H1.5 measures the product we built. It does not modify the product until the measurement says why.

*Revision 1 (pre-participant, reviewer-authorized): baseline verification by production-tree diff instead of HEAD equality; governance-friction scale corrected to 1 = negligible … 5 = very burdensome (removing the inverted "5 = effortless" anchor); condition 6 made computable via product-recorded `confidence_a`/`confidence_b`; Part A timebox frozen at 40 minutes with expiry semantics; provenance columns (task ID, acquisition profile, run timestamps) added to sessions.csv; scored-cohort selection rule frozen. No thresholds changed.*

This protocol implements the frozen H1.5 plan verbatim. It is a bounded qualitative/product-evidence study, not a statistically representative market survey, and not a new runtime gate.

## What H1.5 asks

Whether the H1.1–H1.4 Research Workspace is useful, understandable, inspectable, trustworthy, and operationally tolerable enough to justify continued productization — measured on real people doing representative research work with the actual CLI product.

A negative result is valid product proof. The verdict is `SUPPORTED`, `MIXED`, or `NOT SUPPORTED` per the pre-registered interpretation in this document. Thresholds do not change after sessions.

## Cohort rules

Minimum **6 completed** participant sessions. Up to 8 total, only to replace an incomplete session or satisfy role/task coverage — never because early results are unfavorable.

Coverage requirements:

- All participants must be comfortable enough with a terminal to evaluate the actual H1.2/H1.4 CLI product (not a hypothetical future UI).
- At least 3 regularly perform research, analysis, technical investigation, or evidence synthesis.
- At least 2 have genuine experience reviewing, approving, challenging, or making decisions from research.
- Categories may overlap.

**Scored-cohort selection (frozen):** when more than six sessions complete, the scored cohort is the earliest-completed six-session subset that satisfies the coverage requirements above (completion order is objective). If no six-session subset satisfies coverage, the cohort requirement was never met and replacement sessions must be run. All completed sessions appear in the evidence; the 5/6 and 4/6 bands evaluate only on the scored cohort.

Participants are pseudonymous (`P01`, `P02`, …). Committed evidence excludes names, emails, employer identifiers, recordings, raw personal notes, credentials, private research questions, and full live workspaces.

## Session structure (four parts, same order for every participant)

### Part A — Real research task (scored)

The participant supplies a real question from their own work or interests. Before any NodeChain run, the facilitator records (on the observer sheet, not committed verbatim if sensitive):

1. The question.
2. Why the answer matters to them.
3. What would count as a useful result (their pre-declared usefulness criterion).
4. 2–3 things they expect to learn or decide.
5. Their normal research approach.
6. Rough normal time expectation.

Task constraints: non-sensitive; publicly researchable; substantially answerable through the existing governed academic-source profile; not selected because we already know NodeChain's answer.

Then the participant executes the live product themselves:

```bash
nodechain research run "<their question>" --profile live --workspace <study-workspace>
nodechain research report <run-id> --workspace <study-workspace>
```

They may use `research open`, `runs`, `inspect`, `verify`, `compare`, and `export` as needed. The facilitator gives the standard command cheat sheet (PARTICIPANT_INSTRUCTIONS.md) and nothing more during the scored portion.

**Part A timebox (frozen): 40 minutes** from the first `research run` invocation. At expiry: criterion met before expiry → `useful_result_met=true`; not met at expiry → `useful_result_met=false` and `time_to_useful_elapsed_min` is recorded as 40. The participant may continue working past expiry for the remainder of the study (Parts B–D need a memo); the scored Part A outcome is frozen at expiry.

Clocks: record elapsed time (first `research run` invocation → participant states their pre-declared usefulness criterion is met, or the allotted period ends) AND active operator time (participant actively working, excluding waiting on network/model latency), so latency is never confused with governance overhead.

### Part B — Evidence-inspection task (scored)

After reading the memo, the participant selects one substantive claim from the result and determines, unaided:

1. What does NodeChain claim?
2. What evidence supports or contradicts it?
3. Which source/citation is connected to that evidence?
4. What confidence/uncertainty is recorded?
5. Can the terminal artifact be verified? (They run the verification.)

Success = they trace claim → evidence → source/citation through the product surfaces and correctly run verification. Time is recorded. Facilitator hints during the scored portion mark the task as assisted (see interventions).

### Part C — Repeatability task (scored)

The participant runs the same live brief a second time, then uses the existing comparison/read surfaces (`research compare`, `research inspect`, `research report`) to inspect both runs. The facilitator records, for each run, the product-recorded report confidence level (from the verified memo's confidence statement) as `confidence_a` / `confidence_b`, plus:

- Whether the overall answer is materially consistent.
- Whether the recommendation/conclusion changed.
- Exact-content/source overlap where observable.
- Important source differences.
- Uncertainty differences.
- Whether any changed conclusion is explainable from visible evidence/provenance.
- Participant classification: `equivalent`, `compatible variation`, or `material contradiction`.

Live acquisition is artifact-bounded by H1.3; the question is whether variability stays intelligible and governable, not whether it is deterministic.

### Part D — Controlled governance challenge (scored)

The facilitator generates the fixed scenario pack for this participant (see `scenario_pack/`): one genuine review-required run and one genuine persisted fault/recovery run, both created through existing NodeChain authorities at the frozen baseline — never by manually editing databases.

The participant must:

1. Identify why intervention is required.
2. Locate the relevant fault/risk/uncertainty.
3. Determine whether dispatch occurred (where applicable).
4. Find the review/recovery evidence.
5. Identify the governed next action.
6. Explain what NodeChain knows versus what remains unknown.

Reviewer-comprehension score is 0–4 across: review trigger, evidence/risk, decision authority, outcome.

## Measurement model

Both elapsed time and active operator time are recorded for every timed measure. All instruments and operational definitions live in METRICS_SCHEMA.md and OBSERVER_RUBRIC.md. Facilitator interventions are recorded separately; a task completed only after being told where to look is not an unassisted success.

## Pre-registered interpretation (product decision thresholds, not release gates)

`SUPPORTED` requires ALL of:

1. ≥ 5/6 participants reach their pre-declared useful-result criterion before the 40-minute Part A timebox expires.
2. ≥ 5/6 independently trace a substantive claim through the evidence/source/citation surfaces.
3. ≥ 5/6 score at least 3/4 on the controlled governance-comprehension task.
4. ≥ 5/6 correctly identify fault/recovery next-action truth in the controlled scenario.
5. ≥ 4/6 judge governance value ≥ governance friction (friction: 1 = negligible … 5 = very burdensome; value: 1 = no value … 5 = very high value).
6. No repeat-run pair produces an unexplained materially contradictory conclusion that is high-confidence, where **high-confidence** is deterministic from captured data: the product-recorded report confidence level of either run in the pair is "high" (`confidence_a == "high" OR confidence_b == "high"`).
7. No study session demonstrates a product surface falsely representing runtime/evidence/review/recovery truth.

All 5/6 and 4/6 counts evaluate on the scored cohort defined in the cohort rules (earliest-completed six-session subset satisfying coverage).

`MIXED`: the core value proposition is observable, but one or more usability/comprehension dimensions materially miss those bands without a truth-integrity failure.

`NOT SUPPORTED`: the study fails to demonstrate a usable product proposition (for example, most users cannot reach a useful result or inspect the evidence), or a recurring truth/comprehension problem undermines the governance proposition.

An unfavorable result must not be converted into `SUPPORTED` by changing thresholds after the sessions.

## Product-mutation discipline

No product code changes between participants. Observed gaps are logged (BLOCKER / IMPROVEMENT / IDEA per the analysis rules). If a demonstrated correctness/truth blocker appears, the affected study path pauses; correction is separate authorized work; pre- and post-correction evidence are never silently pooled.

## Provenance

Every recorded run captures: participant ID, task ID, NodeChain SHA, run ID, bundle digest, acquisition profile, model provider/model identity, adapter set, start/end timestamps. In sessions.csv these are the `task_id`, `product_sha`, `run_id_*`, `bundle_digest_*`, `acquisition_profile`, `model_provider`/`model_name`, `adapters_used`, and `run_start_ts_*`/`run_end_ts_*` columns. Run IDs and bundle digests may be retained in committed evidence where they disclose nothing participant-sensitive.

## Analysis and closure

Analysis runs once, after all sessions, showing individual-session distributions (not just averages). RESULTS.md reports every frozen metric; DECISION.md states what the evidence justifies next. Only demonstrated gaps are eligible for implementation promotion. H1.5 introduces no execution-semantic changes; the closure PR carries study/docs artifacts only.
