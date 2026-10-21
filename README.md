# TRACER Security

**Trace-based Runtime Analysis for Continuous Evolution and Release**

This is the skill and implementation artifact for [*Securing Agent-Generated Code
Through Development History*](docs/paper.pdf), with [manuscript sources](https://github.com/pkrajput/ghost_code).
The study release is archived on [Zenodo](https://doi.org/10.5281/zenodo.23530070).
TRACER connects current Python symbols and SAST
findings to recorded structural changes and separately captured development
rationale. A host coding agent investigates and repairs supported defects, then
preserves the repair invariant and executable checks for later maintenance.

## Main results

The SusVibes study contains **3,096 investigator runs** across 387 admitted coding
attempts, seven coding generators, and two security investigators. The table below
uses the **same 345 attempts** with complete original and candidate evaluations
for every configuration and both investigators. Counts come from the official
functional and security evaluations, with verified terminal completion.

| Configuration | DeepSeek FuncPass | DeepSeek SecPass | Gemini FuncPass | Gemini SecPass |
| --- | ---: | ---: | ---: | ---: |
| Original generated code | 342/345 | 68/345 | 342/345 | 68/345 |
| C0 — Current code + SAST + change-informed targets | 341/345 | 71/345 | 341/345 | 70/345 |
| C1 — C0 + temporal AST history | 342/345 | 73/345 | 340/345 | 74/345 |
| C2 — C0 + recorded rationale | 342/345 | **76/345** | 341/345 | **75/345** |
| C3 — C0 + temporal history + recorded rationale | 342/345 | 74/345 | 340/345 | 73/345 |

- **Review coverage.** Change-informed planning includes the reference-vulnerable
  symbol in 366/387 attempts (94.6%), compared with 52/387 (13.4%) primary stock
  SAST symbol overlap. This measures which symbols enter review, not detection
  accuracy or successful repair.
- **Repair.** Recorded rationale achieves the highest verified security pass
  count with both investigators. C0 already receives patch-selected targets, and
  C1–C3 include audit cues alongside their history channels.
- **Maintenance.** On five selected structural-biology components, joint
  feature-and-security-check success improves from **3/5 to 5/5** with repair
  memory, a boundary gate, and one feedback retry. This compares the complete
  workflows, including the extra retry, rather than memory alone.

See the [paper](docs/paper.pdf) for generator and stratum breakdowns, and
[frozen evidence](evidence/README.md) for the underlying populations.

## Quick start

Python 3.10 or newer and Git are required. The evidence helpers need no model
credential and do not execute the analyzed source. GumTree history additionally
requires a JDK with `java` and `javac` available, tested with OpenJDK 11.

```sh
git clone https://github.com/pkrajput/TRACER_skill.git
cd TRACER_skill
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
tracer-security --help
python scripts/smoke.py
```

Make `skills/tracer-security` discoverable by your coding agent, or explicitly
give it [that folder's SKILL.md](skills/tracer-security/SKILL.md). Keep this package installed in the environment
from which the agent runs helpers. For an agent with a local skills directory,
copy that folder there or symlink it to this checkout. This is a portable skill,
not a provider-specific model service. The host supplies its editing, execution,
credentials, and budget controls.

The installation does not start a study campaign. The default commands make
zero model calls. Research engine and provider-adapter sources are included for
inspection and use only through an explicitly configured host.

## Prepare review evidence

Create a diff against the intended base and export scanner findings on the
current source. The scanner binaries and rule packs are installed separately.

```sh
tracer-security index --source /path/to/repo/app.py --path app.py --output local-output/index.json
tracer-security plan --source /path/to/repo --patch submitted.patch --semgrep semgrep.json --codeql codeql.sarif --output local-output/plan.json
```

Scanner inputs are optional. The plan includes changed production symbols even
without warnings. Outputs are immutable, so each invocation needs a fresh path.
The historical study used Semgrep CE 1.101.0 and CodeQL 2.20.0, Python query pack
1.3.4, with the security-extended suite. New scanner versions create a new
configuration and are not an exact replication of the study.

Give the plan and optional history outputs to the host agent through the skill.
It uses current-source assessments and executable checks to qualify edits, then
records the accepted repair's invariant and checks in an external edit note for
future changes.

Install the hash-pinned GumTree 3.0.0 dependencies once from Maven Central.

```sh
python -m security_ground_truth.temporal_security.gumtree_install
tracer-security describe-change before.py after.py --path app.py --event-id commit-or-edit-id --symbol Parser.load --output local-output/change.json
```

For ordinary Git repositories, use a bare, non-shallow cache, a full commit SHA,
and a target list such as `[{"path":"app.py","symbol":"Parser.load"}]`.

```sh
tracer-security prepare-history --repo-cache /path/to/repo.git --cutoff FULL_COMMIT_SHA --targets targets.json --repository-kind ordinary --output local-output/git-history.json
tracer-security prepare-agent --messages messages.json --targets targets.json --source /path/to/repo --output local-output/agent-history.json
```

`prepare-agent --rationale-only` works without GumTree. It accepts compatible
ReAct message lists and preserves observed prose rather than inventing missing
reasoning. Git and agent histories remain separate. The benchmark's withheld
pre-reference implementations must not be introduced as investigator evidence.

## What is included

- `skills/tracer-security` provides the host-agent workflow and maintenance contract.
- `tracer_skill` provides portable command wrappers around the studied helpers.
- `security_ground_truth` preserves the relevant research implementation, including
  source-bound assessments, context packing, runtime checks, and final validation.
- `evidence` contains frozen result summaries, per-cell outcomes, source hashes,
  and manuscript tables. See `evidence/README.md` for populations and limitations.
- `scripts` provides zero-model-cost smoke checks, regression checks, and result
  recomputation.
- `SOURCE_PROVENANCE.json` records the exact copied implementation hashes. The
  research workspace contained uncommitted fixes, so its Git HEAD alone is not
  used as the implementation identity.

## Verify the artifact

```sh
python scripts/check_core.py
python scripts/recompute_results.py
```

These commands run local regression checks and recompute the shared results by
configuration, generator, and stratum from the archived cell records. Neither
command calls a model or launches a benchmark campaign.

The portable wrappers expose the existing mechanisms. They are not a new
benchmark run, and installing the skill alone does not reproduce the measured
model outcomes. Full regeneration needs the published inputs, project containers,
scanner packs, a configured provider, and paid inference. Archived-result
recomputation does not.

## Availability and citation

Rajput, P., & Khan, S. (2026). *Securing Agent-Generated Code Through Development
History*. Zenodo. https://doi.org/10.5281/zenodo.23530070

The DOI preserves the `v0.1.0` release with software, a manuscript snapshot, and
derived study records. This repository also carries subsequent documentation
and manuscript updates. Raw investigator transcripts, complete evaluator logs,
and container exports are outside that deposit.

Code is licensed under [Apache-2.0](LICENSE). See [CITATION.cff](CITATION.cff),
[third-party notices](THIRD_PARTY_NOTICES.md), and
[archive scope](docs/ARCHIVAL_RELEASE.md) for citation, dependencies, and evidence
availability.
