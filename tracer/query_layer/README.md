# Query recorded rationale

`codegraph-query` finds code anchors, follows a compatible code graph when one
is available, gathers linked development steps, and ranks the evidence. It can
produce a template answer without an LLM.

This component requires a compatible `codebase-memory-mcp` graph for the same
repository and an existing TRACER recording. The basic recorder demo does not
create that graph. From the artifact root, after installing `./tracer`:

```bash
python -m pip install -e ./tracer/query_layer
codegraph-query "Why was the set approach replaced?" \
  --repo /path/to/recorded/repo --graph-db /path/to/graph.db --anchor unique.py \
  --embedding-model hash --no-llm
```

The hash ranker is deterministic and offline; it is useful for the example but
is not a semantic language model. The graph is required even when using a file
anchor. Use `codegraph-trace history` for a graph-free view of recorded rationale.

For model-based ranking, install `./tracer[embeddings]` and select an embedding
model. For an LLM-generated answer, install `./tracer/query_layer[llm]`, configure
your provider credentials, pass `--llm-model <provider/model>`, and omit
`--no-llm`. That path sends retrieved context to the configured provider and may
incur API charges. It is not exercised by the offline demo or unit tests.

Run `codegraph-query --help` for all options.
