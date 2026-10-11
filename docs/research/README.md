# Research scope and reproduction

The working paper, **Development Histories as Software Evidence**, presents
TRACER as reusable development-history infrastructure and ghost-script analysis
as an initial application. This source release makes the tool components and
small examples available separately from the full research data.

## Three levels of use

| Level | Available in this repository | Additional requirements |
|---|---|---|
| Try recording and analysis | Synthetic examples and source | Python 3.10+; Git for the recorder |
| Rerun study analyses | AST/history discovery, embedded-definition analysis, and evidence-joining scripts | Original trajectory archive, retained-file inventories, saved deletion evidence, and any required baseline-source cache |
| Rerun agents or deletion trials | Recording connector source | Separately provisioned mini-SWE-agent, task environments, model access, evaluation harness, and study configuration |

The demos validate the documented workflows. They do not reproduce the empirical
counts. The source ZIP excludes empirical trajectories, saved evaluation results,
and language-review records. These are prepared separately in
`tracer-ghost-data-anonymous.zip`, with an evidence inventory, released-file
checksums, and an offline verification script. Extract its `ghost_code_data/`
directory alongside the code directory and follow its `README.md`.

Preparing the companion ZIP does not publish it: no deposit URL or DOI is claimed
here. The data package contains an anonymized derivative of the recorded evidence;
its sanitization report distinguishes released bytes from historical hashes.

## Evidence stages

1. **Capture:** preserve action records and before/after source snapshots,
   including captured untracked and temporary files.
2. **Discovery:** screen retained Python files for source-writing effects.
   Discovery does not use helper nominations or deletion outcomes as labels.
3. **History association:** link an invoked helper version and its resolved write
   destination to a target change within the recorded action interval.
4. **Characterization:** compare complete definitions embedded in helper strings
   with product definitions and follow those definitions through later revisions.
5. **Redundancy audit:** join saved valid deletion outcomes under the same oracle.
6. **Language review:** examine recorded explanations with source provenance and
   verify selected interpretations against the code and action context.

See [the analysis guide](../../ghost_analysis/README.md) for executable commands
and required input layout. The [mini-SWE-agent connector
guide](../../connectors/mini_swe_agent/README.md) documents the snapshot capture
format. The TRACER decision ledger was outside this empirical evaluation.

## Reported findings and their scope

The archive contains 240 runs: 12 model configurations on 20 SWE-bench Verified
tasks across eight repositories. The analyzed cohort contains 88 reconstructable
endpoints with matching passing outcomes across two saved evaluations.

The captured inventory supplies 1,695 retained source-file occurrences, including
1,662 Python occurrences. AST screening finds 65 candidates; history supports
62 helpers across 40 runs. Those recover the 62 previously validated reference
helpers. Three further candidates remain unresolved and have unknown deletion
status. Counts refer to occurrences of a file in a run, not globally unique files.

Complete embedded definitions link to product code for 25 helpers: 20 match the
final implementation and five are superseded. The other 37 remain unlinked by
that extractor. Saved individual deletion checks support task-level redundancy
for all 62; combined deletion checks also preserve the recorded outcomes in the
40 affected runs.

Available narration or exposed reasoning occurs at the reference construction
action for 48 helpers; 14 lack it. An author verified five selected language
interpretations. This is not a human-validated annotation of the full cohort;
the cohort-wide interpretations remain provisional. These language-review records
are in the separate data ZIP, rather than the source ZIP.

These findings are taken from the working manuscript and final discovery and
structural-analysis reports. The examples informed prototype development, so
62/62 recovery is retrospective evidence, not an independent precision or recall
estimate. The source preparation does not rerun subject agents or task oracles.

## What is intentionally separate

Earlier experimental work explored helper reuse, source retrieval, and cleanup,
including a FeatureBench extension. Those experiments have different questions
and data requirements. They are outside this source release's SWE-bench
AST/history workflow and should not be read as evaluated TRACER capabilities.

There is no archive DOI or finalized paper citation to cite yet. Once the data
deposit and manuscript metadata are finalized, this page should link them and
record their versions and checksums.
