RESEARCH SOURCE AND SAVED-CANDIDATE REPLAY

frozen_pipeline/ contains the exact maintenance driver, audit scripts and their
local Python import dependencies copied from the research workspace. Hashes and
the source HEAD are recorded in provenance/RESEARCH_SOURCE.json. Source paths
inside this frozen driver refer to the original machine and are preserved for
audit; do not run its paid generation commands as a portable quick start.

Original research files retain their recorded bytes. Six package marker files
were added so an installed TRACER distribution cannot shadow the archived
modules; provenance/RESEARCH_PACKAGING_ADDITIONS.json identifies those additions.

The portable replay helper uses only the candidates and check files in this
complete release. After downloading the complete artifact, set ARTIFACT to its extracted directory:

  ARTIFACT=local-output/tracer-complete-study-2026-10-23

From the code repository root:

  python3 scripts/replay_rq5.py --artifact-root "$ARTIFACT"
  python3 scripts/replay_rq5.py --artifact-root "$ARTIFACT" --case rfdiffusion_checkpoint__A --arm B0

These commands list/preview without launching Docker. To actually replay:

  python3 scripts/replay_rq5.py --artifact-root "$ARTIFACT" --case rfdiffusion_checkpoint__A --arm B0 --execute --out /tmp/tracer-rf-b0

Docker must be running and the recorded Linux/amd64 image must already exist
locally. DOCKER_HOST is inherited from the caller when needed. The default image
identity is recorded in environment/recorded_image.json. Every executed check
uses a read-only filesystem, read-only candidate/evaluator mounts, no network,
an unprivileged user and bounded resources. No model calls or credentials are used.

The RFdiffusion B0 final proposal should pass ordinary and feature checks and
fail both boundary checks. Matching that failure is successful evidence replay,
not a successful repair. B3 passes all four checks. Use --arm B3 and a fresh
output path to inspect that contrast. --attempt first selects the first proposal.
Saved cases with no executable candidate retain their original application and
unknown outcomes and cannot be replayed as candidate code.

A reconstruction Dockerfile pins the main scientific Python package versions.
Building it requires network access and creates a new image, potentially with
different transitive/system dependencies. It is not claimed to reproduce the
historical SHA-256 image identity. Example:

  docker build --platform linux/amd64 -t tracer-rq5-rebuilt:20261023 research/environment
  python3 scripts/replay_rq5.py --artifact-root "$ARTIFACT" --case rfdiffusion_checkpoint__A --arm B3 --image tracer-rq5-rebuilt:20261023 --execute --out /tmp/tracer-rf-b3-rebuilt

The recipe is included for convenience; use the exact historical image for an
environment-identical replay. Container exports are not included in this release.
Offline recomputation of all reported counts does not require any Docker image:

  python3 scripts/verify_release.py --artifact-root "$ARTIFACT"

Frozen protocol tests (no Docker or model access):

  python3 scripts/check_research.py
