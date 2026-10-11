# Ghost-script analysis

Find Python scripts that can rewrite source, connect them to recorded changes,
and inspect the implementations they retain. This is an analysis built on
development-history evidence; [TRACER](../tracer/README.md) is the broader
recording and review infrastructure.

**Python 3.10+; standard library only.** Run these commands from the repository
root. The analyzer parses source and recorded commands without executing them.

## Try it in a minute

```sh
python3 -m ghost_analysis demo --out outputs/ghost-demo
```

The demo constructs a tiny, entirely synthetic trajectory and runs the same
discovery engine used by the research scripts. No archive download, model,
API key, Docker image, or benchmark environment is needed.

```text
Static candidates: 2; history-supported helpers: 1.
writer.py: recorded write with a target change; embedded implementation is superseded.
noop.py: possible writer, but its recorded invocation leaves the target unchanged.
data.py: source-writing text stored as data; no executable write found.
Task redundancy: unknown for every file. The demo includes no deletion evidence.
```

Open `outputs/ghost-demo/discovery/summary.json` for counts,
`outputs/ghost-demo/discovery/discovery.jsonl` for per-file evidence, and
`outputs/ghost-demo/correspondence.json` for the embedded implementation match.
The retained helper writes an `answer()` definition returning `2`; a later
snapshot changes that definition to return `3`. Its payload is therefore
**superseded**. This says nothing about whether deleting the helper is safe.
Use a new output directory for each run.

## Screen your own files

```sh
python3 -m ghost_analysis scan /path/to/helper.py
python3 -m ghost_analysis scan /path/to/repository --json outputs/screen.json
```

The screen recursively inspects `.py` files, skipping common environment/build
directories and nested symlinks. It reports possible writes to statically
resolved Python paths, source-read origins, transformations, unknown calls, and
parse errors. It does not determine which files were newly introduced or retained;
choose your input scope deliberately. A normal source generator can be a candidate.
Files it cannot parse remain unknown. JSON output must be a new file.

Supported examples include `open(...).write(...)`, `Path.write_text(...)`,
read/replace/write transformations, and selected list mutations. Branches are
joined; loops are approximated once. Dynamic paths, complex aliases, indirect
calls, and unsupported APIs can prevent a match. A clean screen does not certify
the absence of helper scripts or ghost code.

## Compare an embedded implementation

Supply the helper and the product file immediately before its recorded action,
immediately after it, and at the final endpoint:

```sh
python3 -m ghost_analysis compare \
  --helper ghost_analysis/examples/writer.py \
  --before ghost_analysis/examples/before.py \
  --after ghost_analysis/examples/after.py \
  --final ghost_analysis/examples/final.py
```

This parses complete functions/classes embedded in strings and compares their
AST fingerprints with product definitions. The example yields `answer` with
`introduced_in_after: true` and `endpoint_status: "superseded"`. Formatting and
comments do not affect the fingerprint; changed names, literals, operators, and
docstrings do. An exact match is structural correspondence. Review whether a
literal is replacement code, a search pattern, or unused data before attributing
the change to the helper. Missing complete definitions remain unlinked.

## Three separate questions

| Question | Evidence | What the result means |
| --- | --- | --- |
| Can this script write Python source? | Bounded AST analysis | A source-writing **candidate** |
| Was it associated with a recorded source change? | Direct invocation, matching helper bytes, resolved write target, before/after snapshots | A **history-supported helper**, with action-interval attribution |
| Can it be removed from the final solution? | Separate valid deletion trial with the same fixed passing oracle outcomes | **Task-oracle redundancy**, the study's operational ghost-script criterion |

Current or superseded payloads describe a fourth property: correspondence to the
final implementation. Either kind can be task redundant. A history association
does not prove isolated causality when an action contains several operations.
This package emits evidence for inspection; the static commands do not delete
files, run benchmark tests, or label candidates safe to remove.

## Analyze a recorded study archive

[REPRODUCING.md](REPRODUCING.md) describes the external input layout, discovery,
structural characterization, and saved-oracle validation commands. Those scripts
expect the recorded mini-SWE-agent study format. The TRACER recorder's general
history database is a different interface; it is not accepted directly by this
archive importer. The demo demonstrates the required archive and batch layout.

The package includes the existing SWE-bench research analysis source. Original
benchmark recordings, oracle results, product-source evidence, and qualitative
author-review records are distributed in the separate
`tracer-ghost-data-anonymous.zip`, rather than this source ZIP. The demo is an implementation example,
not empirical replication of the paper.

## Tests and code map

```sh
python3 -m unittest discover -s ghost_analysis/tests -v
```

| File | Purpose |
| --- | --- |
| `cli.py`, `demo.py` | Portable screen, comparison, and synthetic walkthrough |
| `helper_ast.py` | Bounded possible-write analysis |
| `structure.py` | Embedded definitions and AST identity |
| `discover_helpers.py` | Inventory-wide AST/history discovery |
| `swe.py` | Archived helper characterization and definition histories |
| `validate_discovery.py` | Compare discovery with separately supplied reference evidence |
| `validate_and_annotate.py` | Original fixed-cohort source checks and review annotations |
| `paper_results.py` | Audit saved oracle outcome vectors and join structural results |

The research modules originate from the structural-study implementation;
release changes add package imports, portable entry points, synthetic examples,
and usability tests. The old helper reuse, retrieval-interference, and
greedy-cleanup experiments are separate from this AST/history analysis and are
not included here.
