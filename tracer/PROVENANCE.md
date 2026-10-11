# TRACER source provenance

The release selects these paths from the user-supplied `TRACER.zip` archive:

| Archive path | Release path | Scope |
| --- | --- | --- |
| `TRACER/codegraph_trace/` | `codegraph_trace/` | Recorder, stores, review, panel, OpenHands adapter, experimental sync client |
| `TRACER/query_layer/codegraph_query/` | `query_layer/codegraph_query/` | Graph-based question answering |
| `TRACER/query_layer/tests/` | `query_layer/tests/` | Query tests |
| `TRACER/extension/src/` | `extension/src/` | VS Code extension source |
| `TRACER/extension/` build metadata | `extension/` | TypeScript, npm, and VS Code development configuration |
| `TRACER/tests/` | `tests/` | Recorder and integration tests; historical experiment tests excluded |

The [source inventory](source_inventory.json) records the SHA-256 of each
selected original file, its archive path, and whether it was adapted for this
release. It omits newly authored release documentation, demo, and regression
tests. Original code comments and dependency notices are preserved.
Hashes describe the original archive bytes; Git may normalize text line endings
in the released checkout according to the root `.gitattributes`.

Release adaptations:

- Replaced the monolithic dependency list with a standard-library base install
  and optional `panel`, `embeddings`, `languages`, and `sync` extras.
- Added an isolated, offline example that records and compares two approaches.
- Rewrote usage documents around the released paths and verified commands.
- Removed the research project's hosted sync endpoint as a default. Sync now
  requires explicit configuration, and environment overrides apply even when a
  saved configuration exists.
- Replaced workstation-specific VS Code launch paths with a portable launch
  configuration.
- Replaced personal and organization identifiers in examples, test fixtures,
  and extension metadata with neutral placeholders.
- Added Apache-2.0 metadata and license copies for independently built Python
  packages, as selected by the artifact owner.

Not selected: Python environments, Node dependencies, caches, compiled output,
private trace stores, trajectory datasets, paper drafts, archived demos,
Firebase deployment files, and the historical experiment runner. The separate
analysis directory provides the release's Ghost Code measurement workflow.
