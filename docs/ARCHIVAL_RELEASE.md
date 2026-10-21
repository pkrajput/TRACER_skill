# ICSE 2027 archival release preparation

Policy checked on 21 October 2026 against the official
[SEIP call](https://conf.researchr.org/track/icse-2027/icse-2027-seip),
[Open Science policy](https://conf.researchr.org/track/icse-2027/icse-2027-icse-2027-open-science-policies), and
[Artifact Evaluation call](https://conf.researchr.org/track/icse-2027/icse-2027-artifact-evaluation).

The Open Science policy asks every submission to include a Data Availability
section after the conclusion. It encourages availability at submission and
public availability after acceptance, while permitting explained restrictions.
GitHub alone is not an archival repository. A DOI-backed deposit such as Zenodo
is recommended. The policy does not make Zenodo itself a mandatory provider.

Accepted SEIP papers may separately submit artifacts for evaluation. Registration
is listed for 22 January 2027 and submission for 29 January 2027. The Available
badge requires a permanence plan and stable identifier. No badge is presently
claimed. Containerized setup, clear instructions, license terms, and a quick-start
test support the Functional/Reusable evaluation.

## Deposit plan

1. Publish the reviewed skill repository and create a versioned release. Archive
   that exact version on Zenodo or another preserved service. Include the source
   checksum manifest, setup instructions, tests, citation metadata, and license.
2. Deposit the study evidence separately if it is too large for the code release.
   Include cohort manifests, per-cell outcome and terminal-completion records,
   scanner manifests, retained/discarded patches, prepared history/rationale
   views, investigator actions, official test logs, and analysis scripts. Include
   the five component repair and feature-evolution records and qualified checks.
3. Preserve upstream dataset/repository licenses. Use pinned identifiers and
   retrieval scripts where redistribution is restricted. Exclude credentials,
   personal caches, unrelated private files, and paid-service keys.
4. Include a manifest of file hashes and document absent or restricted inputs.
   Distinguish reaggregating archived outcomes from regenerating model responses.
5. Insert the actual version DOI and repository release identifier into the
   paper's Data Availability section and `CITATION.cff` after publication. Do not
   claim that an unpublished draft deposit is publicly available.

The current package contains a compact derived-data release, not every raw
trajectory or Docker export. Its row-level recomputation is a concrete starting
point for the archival data deposit. No deposit has been made by this task.

## Repository update

The replacement is prepared in a separate Git worktree. The previous public
artifact commit remains in local history. The prepared push uses an explicit
`--force-with-lease=refs/heads/main:EXPECTED_OLD_SHA`, so it refuses to overwrite
remote changes made since that exact version. Authentication and current public
access must be checked before submission. At preparation time the remote could
not be fetched without credentials, and the browser returned 404.
