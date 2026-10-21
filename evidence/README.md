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
[Zenodo DOI 10.5281/zenodo.23530070](https://doi.org/10.5281/zenodo.23530070).
Full trajectories, patches, test stdout, prepared histories, and component-study
source/check records are outside that deposit. See
[`docs/ARCHIVAL_RELEASE.md`](../docs/ARCHIVAL_RELEASE.md) for the archive scope.
The included rows support result recomputation, not full investigation replay
or independent establishment of vulnerability labels.
