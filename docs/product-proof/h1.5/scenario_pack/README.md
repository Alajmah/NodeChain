# Controlled Scenario Pack — H1.5

Fixed study scenarios for Part D of every session, generated fresh per
participant through existing NodeChain authorities only. No manual database
edits; no invented evidence.

## Contents

- `generate_scenario_pack.py` — generates both scenarios into a
  facilitator-chosen workspace, validates them, writes a provenance
  manifest, and prints the facilitator answer key.

## The two scenarios

1. **Review scenario** — a genuine runtime review-required run over the
   sealed conflicting-evidence corpus. The risk classifier demands human
   review; the run stays paused awaiting an admitted decision.
2. **Fault/recovery scenario** — a genuine `timeout_after_dispatch` fault
   over the sealed timeout corpus. Dispatch really occurred; the
   side-effect ledger holds a non-completed row; `research inspect`
   prints the governed recovery handoff.

## Generating for a participant

```bash
git checkout 5d54190c87136ff217b0d2f4899d6a04ea1b486a   # frozen baseline
python docs/product-proof/h1.5/scenario_pack/generate_scenario_pack.py \
    <study-workspace> P01
```

The script refuses to run on any other product SHA. It prints
`Scenario pack OK.` only when both scenarios validate; a manifest
(`scenario-pack-<id>.json`) records run IDs and the product SHA for the
sessions.csv provenance columns.

Both runs deliberately remain paused: the participant must encounter the
waiting decision and the real recovery state, not their resolutions. Do
not show the printed answer key to the participant during the scored
portion.
