# P0 — Current-Truth Rebaseline

**Status:** FROZEN  
**Date:** 2026-09-12  
**Base:** `master@5d54190c87136ff217b0d2f4899d6a04ea1b486a`  
**Change class:** documentation only

## Objective

Restore the repository's documentation-authority invariant before new production work begins.

The current descriptive surfaces still carry the Horizon-0 baseline pin (`78f9825...`) while also describing later H1.1–H1.4 behavior. `README.md` also retains an obsolete Research Workspace CLI/finalization warning already closed by H0.1. P0 makes current descriptive truth internally consistent at the actual master baseline.

## Files in scope

- `BASELINE.md`
- `ARCHITECTURE.md`
- `README.md`
- `ROADMAP.md`
- `CHANGELOG.md` only for an `[Unreleased]` documentation entry if required by existing repository convention

No production, schema, workflow, test, packaging, release, or runtime file is in scope.

## Required corrections

### BASELINE.md

- baseline date → `2026-09-12`;
- implementation baseline → `5d54190c87136ff217b0d2f4899d6a04ea1b486a`;
- release baseline remains `v3.6.0`;
- implementation-vs-release table updated to the same current pin;
- current Research Workspace description includes H1.1 object model, H1.2 read-side CLI, H1.3 live acquisition profile, and H1.4 verified human-readable report;
- research is explicitly described as the flagship reference application/product-proof surface, not NodeChain's category definition;
- benchmark evidence is recorded as evidence, not as release or implementation truth;
- completed H0 corrections remain closed and are not reintroduced as unfinished seams.

### ARCHITECTURE.md

- baseline date and implementation pin updated to current master;
- current Research Workspace section reflects fixture + live profiles and H1.1–H1.4 product surfaces;
- stale “architectural debt” items already closed by H0.2/H0.4/H0.5 are removed from present-tense unfinished work;
- remaining debt is limited to actually open authority/product gaps;
- research remains one reference product over the general governed runtime.

### README.md

- implementation baseline updated to current master;
- Research Workspace section updated from fixture-only/product-proof wording to the current fixture + live acquisition + read-side + report surfaces;
- obsolete warning that `research review` lacks descriptor-aware reconstruction is removed;
- released version remains `v3.6.0`;
- wording preserves the core product thesis: governed autonomous systems from reusable Harness Nodes.

### ROADMAP.md

- baseline date and pin updated to current master;
- completed H1.1–H1.4 remain out of unfinished work;
- Horizon 1 is reframed so Research Workspace is a flagship reference application rather than the destination platform category;
- near-term ordering reflects the selected program:
  1. Execution-Truth Integrity;
  2. Harness Node Reuse Proof;
  3. reference-product reliability;
  4. node authoring/evaluation/registry after reuse proof;
- broad UI/Studio/enterprise work remains contingent;
- no benchmark finding is promoted automatically without the selected objective stated above.

## Benchmark evidence statement

The documents may summarize the completed benchmark program only with these claim boundaries:

- Runtime / Framework track: NodeChain's strongest evidence is governed execution assurance; comparator advantages remain in replay/fork, social multi-agent abstractions, and distributed workflow infrastructure.
- Research Product track: the tested Research Workspace was not competitive as a completed research-answer product; all six NodeChain live tasks executed to governed terminal failure before substantive answer production because acquisition was repeatedly throttled while inference remained healthy.
- The Research Product result does not invalidate the Harness Node/runtime thesis and does not authorize research feature parity work.

No benchmark score table needs to be copied into current architecture documentation. The benchmark artifacts remain the evidence authority.

## Acceptance gates

P0 passes only if all hold:

1. changed files are documentation only;
2. every present-tense descriptive baseline pin is `5d54190c...` or explicitly historical;
3. no current README warning describes the closed H0.1 CLI defect as open;
4. no current architectural-debt list presents H0.2, H0.4, or H0.5 as unfinished;
5. released-version truth remains `v3.6.0`;
6. H1.1–H1.4 are described as post-v3.6 implementation truth, not back-projected into the release;
7. research is framed as a reference/product-proof application under the general Harness Node platform thesis;
8. roadmap contains unfinished outcomes only;
9. no runtime, schema, test, workflow, package, or release artifact changes;
10. repository documentation-authority precedence remains intact.

## Validation

Before merge:

- inspect the PR diff for documentation-only scope;
- repository-wide search for stale current pin `78f98252173eb38d4284ed92f0fd3343c5c5ce21`; every remaining hit must be explicitly historical/evidence or corrected;
- search for the obsolete Research CLI/finalization warning language;
- search current architecture/roadmap for closed H0 authority items presented as future work;
- verify all links/anchors touched by wording changes;
- no privileged/runtime qualification rerun is required for a documentation-only rebaseline.

## Stop boundary

No P1 production change is permitted in the P0 PR.

After P0 merges, freeze the P1 design/characterization packet before changing side-effect, retry, or memory-write production semantics.
