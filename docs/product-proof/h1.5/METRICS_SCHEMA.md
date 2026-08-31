# Metrics Schema — H1.5 (FROZEN)

Operational definitions for every measured quantity. `sessions.csv` uses exactly these columns; transcribe one row per completed participant session.

## Time model

Every timed metric records BOTH:

- **elapsed** — wall clock from start marker to end marker.
- **active_min** — minutes the participant was actively operating the product, excluding waiting on network/model latency. The facilitator pauses the active clock whenever the only thing happening is the system working.

Latency is the system's; active time is the product's friction.

## Column definitions (sessions.csv)

| Column | Type | Definition |
|---|---|---|
| `participant_id` | str | `P01`–`P08`, pseudonymous |
| `session_date` | ISO date | Session date |
| `roles` | str | `researcher` and/or `reviewer` (self-declared, facilitator-verified) |
| `task_id` | str | `T01`… sequential across the study; maps to the generalized description |
| `task_generalized` | str | Generalized task description (de-identified) |
| `useful_result_met` | bool | Participant reached their PRE-declared usefulness criterion before the Part A timebox expired (40 min; see PROTOCOL.md) |
| `time_to_useful_elapsed_min` | number | First `research run` invocation → criterion stated met; if not met at expiry, fixed at 40 |
| `time_to_useful_active_min` | number | Active-operator portion of the above |
| `report_latency_min` | number | Run start → verified human-readable memo available |
| `inspect_success_independent` | bool | Part B succeeded with zero facilitator hints |
| `inspect_time_active_min` | number | Part B active time |
| `inspect_success_assisted` | bool | Part B succeeded only after a hint |
| `trust_before` | 1–5 | Citation trust before evidence inspection |
| `trust_after` | 1–5 | Citation trust after evidence inspection |
| `verification_comprehension` | bool | Can state what verification establishes AND what it does not |
| `uncertainty_comprehension` | bool | Can explain ≥1 recorded limitation without converting it to certainty |
| `review_score` | 0–4 | Controlled review-scenario comprehension (trigger, evidence/risk, authority, outcome) |
| `fault_all_four` | bool | Fault scenario: identified state, dispatch truth, recovery evidence, governed next action |
| `fault_next_action_correct` | bool | Next-action truth correct |
| `fault_time_active_min` | number | Fault scenario active time |
| `confidence_a` | str | Product-recorded report confidence level for run A (from the verified memo: `confidence_statement.level`) |
| `confidence_b` | str | Product-recorded report confidence level for run B |
| `repeat_classification` | enum | `equivalent` / `compatible_variation` / `material_contradiction` |
| `repeat_explainable` | bool | Any changed conclusion explainable from visible evidence (n/a when unchanged) |
| `governance_friction_rating` | 1–5 | Perceived burden of the governed steps (1 = negligible, 5 = very burdensome) |
| `governance_value_rating` | 1–5 | Perceived value (1 = no value, 5 = very high value) |
| `governance_active_min` | number | Active time on inspect/verify/review/recovery surfaces |
| `adoption_intent` | enum | `yes` / `conditional` / `no` |
| `facilitator_interventions` | int | Total recorded interventions in scored portions |
| `run_id_a` | str | Part A provenance |
| `run_start_ts_a`, `run_end_ts_a` | ISO ts | Part A run start/end |
| `bundle_digest_a` | str | Part A verified bundle digest |
| `run_id_b` | str | Part C (repeat run) provenance |
| `run_start_ts_b`, `run_end_ts_b` | ISO ts | Part C run start/end |
| `bundle_digest_b` | str | Part C verified bundle digest |
| `review_run_id`, `fault_run_id` | str | Part D scenario-pack provenance (fixture profile; the pack manifest carries details) |
| `product_sha` | str | Always `5d54190c87136ff217b0d2f4899d6a04ea1b486a` for scored sessions |
| `acquisition_profile` | str | `live` for the scored Part A/B runs (the only scored acquisition profile in H1.5) |
| `model_provider`, `model_name` | str | Resolved non-secret model identity for the session |
| `adapters_used` | str | Comma list, from the verified memo/report |
| `blockers_observed` | str | Short codes or `-` (details in RESULTS.md, de-identified) |

## Scored-cohort selection (frozen)

When more than six sessions complete, the scored cohort is the **earliest-completed six-session subset that satisfies the cohort coverage requirements** (completion order is objective — session end timestamps). If no six-session subset satisfies coverage, the cohort requirement was never met and replacement sessions must be run. All sessions (scored or not) appear in sessions.csv and RESULTS.md distributions; the 5/6 and 4/6 bands evaluate only on the scored cohort.

## Frozen decision computations

Against the pre-registered bands (see PROTOCOL.md §"Pre-registered interpretation"):

1. `useful = count(useful_result_met) ≥ 5` of the scored cohort (6).
2. `inspect = count(inspect_success_independent) ≥ 5` of 6.
3. `review = count(review_score ≥ 3) ≥ 5` of 6.
4. `fault = count(fault_next_action_correct) ≥ 5` of 6.
5. `value ≥ friction = count(governance_value_rating ≥ governance_friction_rating) ≥ 4` of 6 (friction: 1 = negligible … 5 = very burdensome; value: 1 = no value … 5 = very high value).
6. `no_unexplained_contradiction = no pair with repeat_classification == material_contradiction AND repeat_explainable == false AND high_confidence(pair)`, where **high_confidence(pair)** is deterministic: `confidence_a == "high" OR confidence_b == "high"` — the product-recorded report confidence level (`confidence_statement.level` in the verified memo) of either run in the pair.
7. `no_false_truth = no observed product surface misrepresenting runtime/evidence/review/recovery truth` (facilitator-verified, any session).

`SUPPORTED` ⇔ all seven hold.

## Qualitative classification

Every observation is classified exactly one way:

- `BLOCKER` — false, corrupt, or materially unusable product behavior.
- `IMPROVEMENT` — real observed usability/product gap.
- `IDEA` — participant suggestion without demonstrated product necessity.

A feature request never becomes a roadmap item by virtue of being requested.
