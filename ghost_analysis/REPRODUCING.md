# Reproducing the recorded SWE-bench analysis

The portable [demo](README.md#try-it-in-a-minute) runs immediately. Full study
reproduction additionally requires the recorded archive and saved evaluation
batch. The separate `tracer-ghost-data-anonymous.zip` contains the anonymized
study evidence, baseline-source cache, and an offline verification script;
follow its README for the packaged paths. The source ZIP does not include or
download those empirical inputs.
Use Python 3.10+ with normal assertion checking (do not pass `-O`): the original
research validators use assertions for evidence consistency checks.

## Required input layout

The archive is a ZIP with these members:

```text
ghost_model_families/
  blobs/<sha256>                   # UTF-8 source bytes, content addressed
  runs/<run_id>/events.jsonl       # Ordered commands and snapshot identifiers
  runs/<run_id>/snapshots.jsonl    # Captured file/blob overlays
```

The batch directory provides:

```text
endpoint_census_final.jsonl        # run_id, benchmark="swebench", eligible
file_inventory.jsonl              # run_id, task, path, final_content_sha256, stratum
inputs/swebench/<run_id>/
  initial.json
  final.json
  instance.json                   # repo and immutable base_commit
```

Each action has `event_id`, `sequence`, `command`, `before_snapshot`, and
`after_snapshot`; `exit_code` is retained where available. Each snapshot has
`snapshot_id`, a `files` mapping of repository-relative paths to blob hashes,
and optional `tmp_files` mapping absolute temporary paths to hashes. Explicit
`null` means deletion. An omitted repository path means unchanged base source,
not absence. Repository command paths are rooted at `/testbed` in this format;
this is a recorded path convention, not a required local directory.

Run the demo to inspect a complete minimal example. Its `eligible: true` row is
synthetic input needed by the importer, not an assertion of benchmark success.
Real `eligible` labels must come from separately checked endpoint evaluations.

## Discover first; validate afterward

Set these paths to your own data locations. Run from the repository root:

```sh
STUDY_ARCHIVE=/path/to/recordings.zip
STUDY_BATCH=/path/to/saved-evaluation-batch

python3 -m ghost_analysis.discover_helpers \
  --archive "$STUDY_ARCHIVE" \
  --batch "$STUDY_BATCH" \
  --out outputs/discovery
```

Discovery consumes the eligible-run census and retained-file inventory, discards
prior nomination/origin labels, and does not read deletion results. It inspects
all captured Python versions, supported direct shell invocations, matching helper
bytes, and changes to resolved Python write targets. No captured commands run.
It reads blobs directly from the ZIP and does not unpack the archive.

Outputs include `discovery.jsonl`, `summary.json`, `run_input_hashes.json`, and
`base_sources_used.json`. Hashes identify the supplied inputs and analysis source.
The detector makes no network requests. If an unchanged base file is missing from
the archive, its AST comparison remains unavailable unless you supply
`--base-manifest /path/to/base_sources.json`. The optional manifest maps
`repository@commit:path` keys to `cached` local file paths and `sha256` values;
adapt paths after moving the cache. Each used file is hash checked.

## Characterize retained implementations and audit saved checks

These stages require additional original evidence:

- `nominations.jsonl`, containing the frozen reference helper records, hashes,
  event IDs, strata, and construction metadata;
- the full endpoint census, including task/model coverage;
- `oracle_baselines/<run_id>/{first,repeat}/result.json`;
- `individual_deletions/<run_id>/<candidate>/result.json`;
- `cleanup/<run_id>/evidence.json` and `combined-{0,1}/result.json`.

The saved results must include valid, complete per-check outcome vectors and
consistent `oracle_command_hash` and `test_manifest_hash` fields. These are
original study evidence schemas, not generic test-runner output.

```sh
python3 -m ghost_analysis.swe \
  --archive "$STUDY_ARCHIVE" --batch "$STUDY_BATCH" \
  --out outputs/characterization

python3 -m ghost_analysis.validate_and_annotate \
  --swe outputs/characterization --archive "$STUDY_ARCHIVE"

python3 -m ghost_analysis.paper_results \
  --batch "$STUDY_BATCH" --structural outputs/characterization \
  --out outputs/paper_results.json

python3 -m ghost_analysis.validate_discovery \
  --discovery outputs/discovery --batch "$STUDY_BATCH" \
  --archive "$STUDY_ARCHIVE" --paper-results outputs/paper_results.json \
  --out outputs/discovery-validation
```

`swe.py` characterizes the **previously nominated reference cohort**. It is
separate from inventory-wide discovery. When base source is absent, it can fetch
that source from immutable GitHub commit URLs and cache the bytes and hashes.
This is the one analysis stage with network access. It does not install software
or execute subject code.

`validate_and_annotate.py` preserves the original fixed-cohort inspection rules
and labels. Its annotations represent the study's source review, not independent
human judgments or a validated general-purpose data-flow analysis. Use it for
the matching recorded cohort; do not generalize those labels to arbitrary data.
`paper_results.py` checks saved results rather than rerunning the oracle. The
last step joins reference and deletion evidence after discovery.

Use new output directories and keep the generated evidence paths together.
The historical scripts record local paths in their manifests and are not a
self-contained data distribution. Missing records or failed consistency checks
must be resolved with the original evidence; the demo cannot replace them.
