# Complete study archive

The complete artifact for *Securing Agent-Generated Code Through Development
History* is archived at [Zenodo DOI 10.5281/zenodo.23591518](https://doi.org/10.5281/zenodo.23591518),
published on 23 October 2026. The record credits Prateek Rajput and Shahzeb Khan
and links this existing [code repository](https://github.com/pkrajput/TRACER_skill).

## Published bytes

The record contains `tracer-complete-study-2026-10-23.zip`, 15,260,514 bytes:

```text
SHA-256 32908f4aa48d125c88200d4409a37da7a477a4a8f1f67b4a8abb5803ac635b43
MD5     95fc560265774100aac1d3707abc0288
```

The size and MD5 match the published Zenodo API response saved in
`provenance/ZENODO_23591518.json`. `scripts/fetch_artifact.py` pins the SHA-256,
checks it before extraction, and refuses to replace an existing output directory.
After extraction, `scripts/verify_release.py --artifact-root PATH` verifies all
file hashes and recomputes the benchmark and RQ5 outcomes without model calls.

The ZIP was prepared before its DOI was assigned. Its citation files and paper
snapshot therefore retain the previous DOI and a pending-DOI statement. This
repository and the [paper repository](https://github.com/pkrajput/ghost_code)
now cite the actual new record. These citation updates do not change the published
ZIP's identity or scientific results. The current paper remains 10 text pages and
two reference pages; the manuscript is maintained in the separate repository.

## Included evidence

The archive contains the TRACER Security implementation, all 3,096 published
derived benchmark cells, frozen analyses and tables, and the corrected independent
maintenance study. RQ5 includes ten tasks in five repository clusters, four
conditions and 40 primary cells, plus all original runs and correction stages.
Prompts, model responses, candidate code, executable checks, receipts, original
biology repairs, source audits, upstream licenses and audit lineage are included.

The current code checkout adds the frozen RQ5 driver and its local dependencies,
portable analysis/replay helpers, corrected tables and analysis outputs. Large
raw evidence remains in the pinned archive. One controller-test fixture has a
documented portability patch; production code and test assertions are unchanged.

Result recomputation is self-contained after downloading the archive. Saved
candidate execution additionally requires Docker and the recorded Linux/amd64
image. The supplied reconstruction recipe creates a new environment and does
not promise the original image digest. Fresh model generation requires upstream
project environments, scanners, provider credentials and inference budget.

Raw benchmark investigator transcripts, complete benchmark evaluator logs, full
upstream source trees and container exports are excluded. This restriction does
not apply to the included RQ5 prompts, responses and execution receipts. The
artifact distinguishes observed contract violations from unknown executions and
retains unfavorable outcomes; a fallback is not counted as feature delivery.

## Earlier release and licenses

The earlier [record 23530070](https://doi.org/10.5281/zenodo.23530070) remains
historical provenance. Its `tracer-security-v0.1.0.zip` has SHA-256
`18a314a15dffcbca63d2926d0e9a133ca03cbcc013bef8d76c2f77166ba86adf` and is preserved
inside the complete archive. Its old maintenance comparison is superseded by
the independent factorial evaluation.

Zenodo record metadata uses CC-BY-4.0. TRACER software retains its Apache-2.0
license; upstream source extracts and datasets retain their own terms. The
included LICENSE, THIRD_PARTY_NOTICES and component licenses govern those files.
