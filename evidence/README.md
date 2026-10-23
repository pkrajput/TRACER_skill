# Frozen study evidence

`study_outcomes.json.gz` contains 3,096 allowlisted cell records from the completed
DeepSeek and Gemini campaigns. It preserves terminal-completion evidence,
original/candidate scores, generator/task membership, strata, and nested funnel
facts. It contains no model prompts or raw message transcripts.

`FINAL_MANUSCRIPT_DATA.json` is the frozen derived analysis used by the manuscript.
Its original local paths are provenance strings, not paths required to run the
portable result recomputation. `tables/final_*.tex` are current manuscript tables.
The other CSV panels and `TABLE_CATALOG.json` describe earlier reporting views,
including the interrupted 1,712-cell audit. Their explicit populations must not
be substituted for the final shared 345-attempt cohort.

```sh
python scripts/recompute_results.py
```

This recomputes the shared outcomes by arm, generator, and stratum and the full
nested funnels from the cell rows, asserting agreement with the frozen analysis.
It does not rerun tests or models. Expected shared SecPass counts are
DeepSeek 71/73/76/74 and Gemini 70/74/75/73, with 68 original passes in 345 attempts.

The exporter is `scripts/export_study.py`. It requires explicit paths to the
original final DeepSeek results, Gemini log-rescore results, case manifest, and
frozen analysis. Its source hashes document what was exported. The software and
these derived records are archived at
[Zenodo DOI 10.5281/zenodo.23591518](https://doi.org/10.5281/zenodo.23591518).
Full benchmark trajectories, patches, test stdout and prepared histories are
outside that deposit. Complete independent RQ5 source/check records are included.
See
[`docs/ARCHIVAL_RELEASE.md`](../docs/ARCHIVAL_RELEASE.md) for the archive scope.
The included rows support result recomputation, not full investigation replay
or independent establishment of vulnerability labels.

## Independent RQ5 maintenance study

`rq5/analysis/` contains the corrected ten-task, four-condition comparison and
its protocol audit. The primary cohort contains 24 unchanged initial cells,
12 reruns after feature-oracle corrections, and four adapter replays. Corrections
cover every arm of each affected task. All original outcomes are retained on
Zenodo; no SusVibes continuation contributes to the independent cohort.

Final Func/Sec/Joint counts (out of ten) are B0 7/6/4, B1 9/9/8, B2 6/7/3 and
B3 10/9/9. All conditions allow at most one retry. SecPass combines the saved and
extended boundary checks; JointPass also requires ordinary and feature checks.
Fallback is not feature delivery. The sample is purposive, contains five
repository clusters, and includes naming and reliability contracts alongside
security boundaries. It does not estimate a population-wide treatment effect.

Use `scripts/fetch_artifact.py` and the README's verification commands to obtain
and recompute all primary records. The frozen research code is in `research/`.
