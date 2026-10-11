# TRACER's VS Code extension

This development extension calls the `codegraph-trace` Python CLI to display
reasoning, code history, a local panel, and optional Semgrep findings. It also
records human commits and attempts code-graph reindexing. It is source code for
local development, not a published Marketplace extension.

From the artifact root, first install the Python tool:

```bash
python -m pip install -e './tracer[panel,languages]'
cd tracer/extension
npm ci
npm run compile
```

Open this extension directory in VS Code and press F5 to launch an Extension
Development Host. Open the repository you want to inspect there. Set
`codegraph.pythonPath` to the absolute path of the virtual environment's Python
interpreter. Use **Codegraph: Open Panel** from the command palette.

The extension's manifest requires VS Code 1.85 or later. Its automatic graph
refresh requires a separately installed `codebase-memory-mcp` executable and a
graph for the same repository; configure `codegraph.cbmCliPath` and
`codegraph.graphDbPath` as needed. Semgrep commands require a separate Semgrep
installation. These integrations are optional for the standalone recorder demo.
