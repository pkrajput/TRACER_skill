# TRACER

**Keep the development history that the final diff leaves out.** TRACER links each
recorded development step—its prompt, written rationale, and Git change—to the
files and symbols it touched. Review the history of a function, recover an
abandoned attempt, and inspect which changes survived.

TRACER is the **recording and review tool** in this artifact. The separate
[ghost-script analysis](../ghost_analysis/) examines retained Python source-writing
helpers and their recorded construction history.
The tool's decision ledger and the paper's trajectory metrics are different
analyses; a ledger label alone is not a reproduction of the paper's results.

## Try it in a minute

You need **Python 3.10+ and Git**. Run these commands from the artifact root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./tracer
python tracer/examples/quickstart.py
```

On Windows, create the environment with `py -3 -m venv .venv` and activate it
with `.venv\Scripts\Activate.ps1` in PowerShell.

The example creates a temporary Git repository, records two small Python edits,
and prints the history and decision ledger. First it removes duplicates with a
set; then it replaces that approach to preserve order. The earlier attempt stays
visible even though its implementation disappears from the final file. The
example keeps its repository and prints the path so you can inspect it afterward.

**No API key, model download, code graph, or agent runtime is needed for this
example.** The base recorder uses Python's standard library and Git. Installing
the package may download Python build tools.

## Record your own changes

Record a step after committing its code. Supply the two commits that bound that
step and the rationale you want to preserve:

```bash
codegraph-trace record step-001 \
  --repo /path/to/your/repo \
  --before <commit-before> --after <commit-after> \
  --prompt "Preserve input order while removing duplicates" \
  --reasoning "Use dict.fromkeys to keep the first occurrence of each value" \
  --author agent --no-embeddings

codegraph-trace history unique.py --repo /path/to/your/repo
codegraph-trace versions --repo /path/to/your/repo
codegraph-trace branches derive --repo /path/to/your/repo
codegraph-trace branches show unique.py --repo /path/to/your/repo
```

Replace the paths and commit placeholders. Use a unique step ID for each step;
recording the same ID again updates that step. Use `--author human --no-lock` to
record human provenance without locking the touched nodes. Omitting `--no-lock`
for a human edit enables TRACER's recorded-node lock/proposal workflow.

Record the rationale exposed by your workflow. TRACER does not infer missing
reasoning or recover private model reasoning. It needs the intermediate commits
to preserve intermediate code: a final patch alone cannot recreate the session.

Every CLI example also works as `python -m codegraph_trace.cli ...`.

## What happens under the hood?

```text
prompt + recorded rationale + before/after commits
                       |
                    Git diff
                       |
             changed files / symbols
                       |
          .codegraph-trace/trace.db
                       |
           history / ledger / review / panel
```

- **Recording:** associates the Git diff with a step and stores node links,
  signatures, and snapshots. Pure whitespace reformats do not create code links.
- **Attribution:** Python symbol extraction uses the standard-library AST;
  optional grammars add JavaScript, Java, and CSS. A compatible external
  `codebase-memory-mcp` graph adds code relationships. Unresolved changes retain
  file-level attribution.
- **Decision ledger:** compares recorded additions with the session's final
  state and classifies them as `survived`, `abandoned`, `revised`, or
  `error_retry`. These are operational labels, not judgments of code quality.
- **Review:** exposes rationale alongside code history and abandoned content.

Trace data lives in `<your-repo>/.codegraph-trace/`:

```text
trace.db                 recorded steps, code links, decisions, lineages
snapshots/               per-commit snapshots
chroma/                  optional reasoning embeddings
```

Keep that directory out of source control if it contains private prompts or
code. `codegraph-trace ensure-ignore --repo /path/to/your/repo` adds the ignore
rule and untracks previously tracked trace output.

## Choose the interface you need

| Need | Command or component |
| --- | --- |
| Explain a file or symbol | `codegraph-trace history <file-or-symbol>` |
| Inspect recorded versions | `codegraph-trace versions` |
| Classify surviving and abandoned attempts | `codegraph-trace branches derive`, then `branches show` |
| Assemble a lineage's review bundle | `codegraph-trace review <lineage>` |
| Inspect a local visual panel | `codegraph-trace panel` |
| Import saved OpenHands events | `codegraph-trace replay <events-path>` |
| Search recorded rationale | `codegraph-trace search <question>` with embeddings installed |
| Ask a question using graph-linked evidence | Optional [query layer](query_layer/README.md) |
| Review inside VS Code | Optional [extension](extension/README.md) |

Append `--repo /path/to/your/repo` to commands. Run
`codegraph-trace <command> --help` for the full arguments.

### Local panel

From the artifact root:

```bash
python -m pip install -e './tracer[panel]'
codegraph-trace panel --repo /path/printed/by/the/demo
```

Open the local URL printed in the terminal. It binds to `127.0.0.1` by default;
stop it with Ctrl+C. The demo works without an external graph; graph-dependent
views become richer when a compatible code graph is supplied.
The optional force-directed graph layout loads its JavaScript libraries from
jsDelivr on first use, so that layout needs browser network access.

### Agent integrations

The included adapter reads **OpenHands V0 JSONL events and V1 conversation
directories**. Offline replay expects the latest commits to align with the
parsed steps: one commit per step, in order.

```bash
codegraph-trace replay /path/to/events.jsonl \
  --repo /path/to/aligned/repo --no-embeddings
```

Other agents can call `record` for each step or implement the
[`StepSource`](codegraph_trace/adapters/base.py) interface. There are no bundled
Claude Code or Codex log adapters in this recorder. The artifact also includes a
separate [mini-SWE-agent snapshot adapter](../connectors/mini_swe_agent/README.md);
it imports preserved snapshots and is distinct from TRACER's Git-based `record`
and OpenHands replay paths. Importing arbitrary logs without matching
intermediate code is not supported.

### Optional dependencies

Install only the features you need, from the artifact root:

| Feature | Installation | Notes |
| --- | --- | --- |
| Web panel | `python -m pip install -e './tracer[panel]'` | Local Flask server |
| JS / Java / CSS AST attribution | `python -m pip install -e './tracer[languages]'` | Tree-sitter grammars; Python needs no extra |
| Semantic reasoning search | `python -m pip install -e './tracer[embeddings]'` | ChromaDB + sentence-transformers; first model use may download weights |
| Graph-based question answering | `python -m pip install -e ./tracer/query_layer` | See its README for offline and optional LLM modes |
| Experimental sync client | `python -m pip install -e './tracer[sync]'` | Requires your own compatible relay; see below |

`codegraph-trace flag` joins existing Semgrep findings with the trace; generating
those findings requires a separate Semgrep installation. No Semgrep scan or live
LLM run is part of the offline quickstart.

### Experimental team sync

The `tracer` command is the **optional sync client**; the main recording CLI is
`codegraph-trace`. The artifact preserves this distinction for compatibility.
The client and in-process test transport are included as research source. No
hosted relay is configured or supplied by this release. Set `TRACER_API_URL` or
`tracer config --set api_base_url=...` only when using your own compatible service.
Sync integration has separate deployment, authentication, and SSH-key
requirements and is not part of the supported offline demo.

## Development and tests

From the artifact root:

```bash
python -m pip install -e './tracer[dev,panel,sync,languages]' -e ./tracer/query_layer
python -m pytest tracer/tests tracer/query_layer/tests
```

The suite uses temporary repositories and an in-process sync transport. The live
Firebase test is skipped unless `TRACER_EMULATOR_URL` is set. The ChromaDB test is
skipped when its optional dependency is absent. A hosted sync deployment, live
agent sessions, LLM providers, and downloaded embedding models require separate
integration validation.

## Release scope

This directory contains the recorder, query layer, editor extension source, and
their tests, selected from the supplied TRACER research archive. Private runtime
state, generated traces, bundled environments, build outputs, archived demo
repositories, the hosted Firebase deployment, and historical experiment drivers
are excluded. See [provenance](PROVENANCE.md) for the source inventory and release
adaptations. The code is released under [Apache-2.0](../LICENSE).
