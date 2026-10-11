# Source provenance and third-party components

This release separates three pieces of the research workspace:

| Component | Source lineage |
|---|---|
| `tracer/` | TRACER research source archive; the Python package retains the `codegraph_trace` name |
| `ghost_analysis/` | SWE-bench structural-study scripts for AST/history discovery and embedded-definition analysis |
| `connectors/mini_swe_agent/` | mini-SWE-agent snapshot recorder from the ghost-script study |
| `docs/assets/tracer_ghost_script_overview-1.png` | Author-supplied architecture and study overview figure |

The release adds portable packaging, examples, and documentation around those
components. It does not bundle the original agent workspaces or third-party
subject repositories.

TRACER integrates with the `codebase-memory-mcp` structural index. Optional
features use additional packages declared in their component metadata. The
mini-SWE-agent connector targets a separately installed agent and environment;
the upstream agent source is not vendored here. Each external dependency retains
its own license. Preserve any existing source notices when redistributing.

The maintainer has selected the Apache License, Version 2.0, for this release;
see [LICENSE](LICENSE). This project license does not replace third-party terms.
