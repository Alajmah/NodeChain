# Clean Republication — Gate A Decision Record

This record documents the inputs and decisions used to prepare the verified
clean publication tree. It is committed *into* the candidate tree so that the
basis for the publication is reviewable alongside the code.

The resulting candidate commit SHA and tree SHA are **not** recorded here. A
commit cannot contain its own SHA. Those values are written to a separate
external evidence file (`gate-a-publication-evidence.txt`) after the commit
exists.

## Baseline

```text
baseline commit:
f424fe13ef3fb86ba857034d57ef9c2fd9fe83a2

decontamination ancestor:
fedc0d4c6e231cf98fa4e09d195f22b4f534bfea
```

The baseline `f424fe13` descends from `fedc0d4c`, which removed
`.ouroboros/state.db` from tracking via `git rm` (16,199,680-byte blob → 0)
and added ignore rules for the database, `.zcode/`, and `.benchmarks/`.

`f424fe13` is a suitable **starting baseline** but is **not** a publication-
ready snapshot: `fedc0d4c`'s ignore rule for `.zcode/` did not untrack files
that were already tracked, and `.nodechain/` was neither untracked nor ignored.

## Reference-document convergence

```text
implementation-aligned reference input:
18b5dab62f054d93b23c7cf803cb78ef511ac3c8

superseded reference input:
eadf15e15b5ab053b3af84a1bf44d3f99c5229d7

resulting canonical path:
NodeChain_Reference_Implementation.md

decision:
replace wholesale; no Gate A section-level merge

rationale:
the implementation contains the five academic adapters and domain-routing
components described by the parenthesized document and does not contain the
Tavily adapter specified by the superseded document.
```

Verified against the `f424fe13` source tree:

- implemented academic adapters (5): `arxiv`, `crossref`, `openalex`,
  `pubmed`, `semantic_scholar` — matches the parenthesized document;
- `domain_router.py` and `domain_classifier.py` exist — matches the
  parenthesized document;
- no `tavily` adapter exists in source — contradicts the superseded document.

The superseded document described a different, unimplemented design. Do not
infer authority from the filename: the parenthesized `(1)` file held the
implementation-aligned content; the canonical-named file did not.

## Retained contractual fixture

```text
retained contractual fixture:
data/v2.70_baseline/frozen_comparison_fixture.json

retained fixture blob:
8530515dd0437f458ea8c4b6a44ccc026f787116
```

This is an intentional frozen v2.70 comparison fixture (contractual regression
baseline), not generated runtime state. It must not be grouped with local
runtime artifacts.

## Removed local metadata and stray artifacts

Untracked via `git rm -r --cached` (local copies may remain only in the legacy
worktree; they must not enter the clean archive or replacement repository):

```text
.zcode/plans/plan-sess_25eef162-1b5c-465b-8777-125f9731f22f.md
.zcode/plans/plan-sess_2fd837b3-05ba-420a-b61d-396402d74630.md
.zcode/plans/plan-sess_5de14c3a-0820-42fc-9490-cb3b61a879d9.md
.nodechain/eval/node-scorecards/latest.json
```

Deleted:

```text
sandbox_test_output.txt              (stray 4-byte artifact, content "test")
NodeChain_Reference_Implementation (1).md   (superseded after convergence)
```

The removed files belong to the restricted sensitive evidence set, not the
publication, but they are distinct in kind:

- `.zcode/plans/*` — session-linked planning and implementation records;
- `.nodechain/eval/node-scorecards/latest.json` — generated node-evaluation
  scorecard cache.

## Permanent publication-tree guard

A permanent guard is added at `scripts/check_publication_tree.py` with tests at
`tests/test_publication_tree_guard.py`. The guard inspects the **committed
tree** (`git ls-tree -r -z --name-only <ref>`), not the working directory or
`.gitignore`, because an ignore rule does not remove a file that is already
tracked.

Forbidden categories:

```text
.ouroboros/
.zcode/
.nodechain/
.benchmarks/
*.db
*.sqlite
*.sqlite3
sandbox_test_output.txt
browser-style duplicate filenames: Name (1).ext, Name (2).ext, …
```

Extension matching is case-insensitive. The duplicate-name classifier covers
`<name> (<n>)<optional-ext>` where `<n>` starts at 1; ordinary parenthesized
filenames without the numeric duplicate suffix remain allowed.

Exit-code contract: `0` clean / `1` violations / `2` git or execution error.

## Restricted-evidence retention and destruction

One encrypted offline copy of the legacy repository (including the
contaminated `.ouroboros/state.db` blob and the removed `.zcode` / `.nodechain`
metadata) is retained **only until 7 calendar days after**:

1. the clean repository passes fresh-clone qualification;
2. the canonical repository name is transferred;
3. the old GitHub repository is retired; and
4. development has resumed successfully from a clean clone.

After that trigger:

- destroy the raw contaminated repository archive;
- destroy or quarantine all old development clones;
- destroy the retained local-only database evidence;
- retain only a sanitized permanent record (old repository identity,
  contaminated blob identifiers, accepted incident conclusions, source
  publication SHA, new root SHA, migration manifest and hashes, destruction
  date).

## What this commit does not do

- No runtime or application behavior changes. No file under `src/` is modified.
- The resulting candidate commit SHA is not recorded here (self-reference).
- No replacement repository is initialized or published by this commit.
