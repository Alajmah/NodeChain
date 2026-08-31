# Observer Rubric — H1.5 Facilitator Sheet (FROZEN)

One sheet per participant. Transcribe de-identified measurements into `sessions.csv` after the session; keep the raw sheet out of the repository.

## Header (per session)

```
Participant ID: P__            Date: ____  Product SHA: 5d54190…
Facilitator: ____              Session start / end: ____
Role coverage: [ ] researcher/analyst  [ ] reviewer/decision-maker
```

## Part A — Real research task

Record BEFORE the run:

```
Question (generalize later if sensitive): ______________________
Why it matters: ______________________
Pre-declared usefulness criterion (their words): ______________________
Expects to learn/decide (2–3): ______________________
Normal approach: ______________________
Normal time expectation: ____
```

During/after:

```
Run ID: ____   Bundle digest: ____   Profile: live
Model provider/model: ____   Adapters used (from report): ____
Elapsed start (first research run invoked): ____  End: ____
Active operator time (exclude waiting on network/model): ____ min
Usefulness criterion met: [ ] yes  [ ] no — their words on why: ____
Facilitator interventions during A (count + what): ____
Live run ID 2 (Part C pre-registration may reuse): ____
```

## Part B — Evidence-inspection task

Success criteria (all must hold for "independent success"):

```
[ ] Correctly states what the claim says
[ ] Finds the supporting/contradicting evidence
[ ] Connects evidence → source/citation
[ ] States the recorded confidence/uncertainty
[ ] Runs bundle verification themselves and reports the result
Time from task start → completion: ____ min (active)
Assisted? [ ] no  [ ] yes — what was the hint: ____
Trust rating BEFORE inspection (1–5): ____   AFTER: ____ (their explanation: ____)
```

## Part C — Repeatability task

```
Second run ID: ____   Bundle digest: ____
Answer materially consistent: [ ] yes  [ ] no
Recommendation/conclusion changed: [ ] no  [ ] yes → how: ____
Source overlap observed: ____   Important source differences: ____
Uncertainty differences: ____
Changed conclusion explainable from visible evidence: [ ] yes [ ] no [ ] n/a
Participant classification: [ ] equivalent  [ ] compatible variation  [ ] material contradiction
Their reasoning (short): ______________________
```

## Part D — Controlled governance challenge

Scenario pack generated for this participant: review run `____`, fault/recovery run `____`.

Review scenario — score 1 point per item (0–4):

```
[ ] Identifies WHY intervention is required (the review trigger)
[ ] Locates the evidence/risk/uncertainty driving it
[ ] Identifies the decision authority (who may act and through what command)
[ ] States the governed outcome correctly (what happens on approve/reject)
Review score: __/4      Time: ____ min (active)
```

Fault/recovery scenario:

```
[ ] Identifies the fault state and type
[ ] Determines whether dispatch occurred
[ ] Finds the recovery evidence
[ ] Identifies the governed next action correctly
Fault/recovery success: [ ] all four  [ ] partial (which: ____)
Next-action truth correct: [ ] yes  [ ] no
Time: ____ min (active)
```

## Closing (post-survey debrief — one line each)

```
Governance friction (1–5): ____   Active time on inspect/verify/review/recovery: ____ min
Governance value (1–5): ____   Their explanation: ____
Uncertainty comprehension: [ ] can explain a recorded limitation without converting it to certainty
Verification comprehension: [ ] can state what verification establishes AND what it does not
Adoption intent: [ ] yes  [ ] conditional  [ ] no — reason: ____
Qualitative observations (mark each BLOCKER / IMPROVEMENT / IDEA): ____
```

## Facilitator discipline

- Never touch the keyboard during scored tasks. If the participant is stuck, you may acknowledge the stuck point and record it; a hint about WHERE to look converts the task to "assisted" and must be recorded.
- Record interventions honestly. An assisted completion is data, not a failure of the study.
- If the product shows false or corrupt truth (a BLOCKER), stop the affected path, preserve the workspace, and follow the blocker procedure in PROTOCOL.md.
