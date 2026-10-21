# TRACER Security

**Trace-based Runtime Analysis for Continuous Evolution and Release**

This is the skill and implementation artifact for [*Securing Agent-Generated Code
Through Development History*](docs/paper.pdf), with [manuscript sources](https://github.com/pkrajput/ghost_code).
TRACER connects current Python symbols and SAST
findings to recorded structural changes and separately captured development
rationale. A host coding agent investigates and repairs supported defects, then
preserves the repair invariant and executable checks for later maintenance.

## Install and use

Python 3.10 or newer and Git are required. The evidence helpers need no model
credential and do not execute the analyzed source. GumTree history additionally
requires a JDK with `java` and `javac` available, tested with OpenJDK 11.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m tracer_skill.cli --help
python scripts/smoke.py
python scripts/check_core.py
python scripts/recompute_results.py
```

Make `skills/tracer-security` discoverable by your coding agent, or explicitly
give it that folder's `SKILL.md`. Keep this package installed in the environment
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

The paper reports 387 admitted attempts, 3,096 recorded investigator cells, and
345 attempts with complete original and eight-arm candidate outcomes. C0 already
receives changed-symbol targets. It is not stock SAST alone. C1–C3 also carry
audit cues, so the comparison does not isolate each channel from those cues.

The portable wrappers expose the existing mechanisms. They are not a new
benchmark run, and installing the skill alone does not reproduce the measured
model outcomes. Full regeneration needs the published inputs, project containers,
scanner packs, a configured provider, and paid inference. Archived-result
recomputation does not.

## Availability and citation

This release replaces the earlier NIER-focused artifact layout. Its predecessor
remains in Git history at `3fe2b3230991f771b92825ecffd312a68fd0713e`.
The repository is currently named `ghost_code_artifact`. A future rename to
`TRACER_skill` does not change the package or skill names.

See `CITATION.cff`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, and
`docs/ARCHIVAL_RELEASE.md`. No DOI or artifact badge is claimed before deposit
and evaluation. Raw investigator trajectories, complete evaluator logs, and
container exports require a separate archival release. They are not silently
substituted by the compact result tables.
