# mini-SWE-agent recording connector

Record the repository states and tool observations from a mini-SWE-agent run so
that intermediate artifacts can be studied after the agent finishes.

This is an **optional source integration** preserved from the experiment, not a
standalone benchmark launcher. The [TRACER package](../../tracer/) provides the
general trace and decision-ledger tooling; [ghost-code analysis](../../ghost_analysis/)
studies the artifacts that remain in a run. This connector supplies a separate
snapshot history from mini-SWE-agent.

## Try the offline check

From the repository root, with Python 3.10 or newer:

```bash
python3 -m connectors.mini_swe_agent.smoke
```

It checks content-addressed storage, reconstruction of an edited/deleted/added
file, and budget accounting with an ambiguous request. It uses a temporary
directory, the Python standard library, and no API calls or Docker containers.
This checks the reusable storage and accounting components; it does not validate
a live mini-SWE-agent integration.

## What is included

| File | Responsibility |
| --- | --- |
| `mini_tracer_adapter.py` | Record actions, model requests, model-visible observations, and snapshot references; export action records as `Step`-shaped dictionaries. |
| `snapshots.py` | Capture repository deltas and selected `/tmp` files through `docker exec`; store file contents by SHA-256; reconstruct a repository state. |
| `budget_gateway.py` | Reserve a request's estimated cost before dispatch and keep unresolved charges in a SQLite ledger. |
| `bounded_http.py` | Bound the HTTP request's elapsed time and preserve transport metadata. |

These are the canonical `ghost_model_families/src/` sources from the experiment
archive, including the later billable-output reservation correction. Original
hashes and the small import adjustment are listed in [SOURCE.json](SOURCE.json).
No benchmark repositories, run histories, provider configurations, credentials,
or third-party agent source are bundled here. The release's [Apache-2.0
license](../../LICENSE) applies to this connector; independently installed
dependencies retain their own licenses.

## Connect an existing mini-SWE-agent runner

Real collection needs Docker, an already running task container, an independently
installed compatible mini-SWE-agent, `requests`, and the provider credentials
required by your model. The manuscript identifies **mini-SWE-agent 2.4.6** as the
study version. Release checks verified imports and in-memory action recording
with that version. Live provider and Docker execution have not been validated
as part of release preparation.

In an activated virtual environment, install the optional dependencies:

```bash
python -m pip install -r connectors/mini_swe_agent/requirements.txt
```

The connector imports these mini-SWE-agent APIs:

```text
minisweagent.agents.default.DefaultAgent
minisweagent.exceptions.LimitsExceeded, Submitted
minisweagent.models.GLOBAL_MODEL_STATS
minisweagent.models.openrouter_model.BASH_TOOL, OpenRouterModel, OpenRouterAPIError
```

It relies on `DefaultAgent.execute_actions(message)` and on the environment's
`execute(action, cwd, timeout=...)` and `_check_finished(output)` methods. The
OpenRouter recorder also uses `_prepare_messages_for_api`, `_parse_actions`,
`_api_url`, `_api_key`, and `config`. These private hooks make this integration
sensitive to upstream changes.

Once those dependencies are installed, check the import without calling a model:

```bash
python3 -c "from connectors.mini_swe_agent.mini_tracer_adapter import RecordingAgent, RecordingDockerEnvironment, RecordingOpenRouterModel"
```

The following integration fragment assumes your existing runner has prepared
`inner_env` (a mini-SWE-agent Docker environment), `base_commit` (the task's Git
base), `model`, and `agent_config` (its normal agent configuration):

```python
from pathlib import Path

from connectors.mini_swe_agent.snapshots import BlobStore, ContainerSnapshotter
from connectors.mini_swe_agent.mini_tracer_adapter import (
    RecordingAgent,
    RecordingDockerEnvironment,
    RunRecorder,
)

output = Path("outputs/mini-swe")
blobs = BlobStore(output / "blobs")
recorder = RunRecorder(output / "runs" / "example", blobs, run_id="example")
snapshotter = ContainerSnapshotter(
    container_id=inner_env.container_id,
    repo_dir="/testbed",
    base_commit=base_commit,
    blob_store=blobs,
)
environment = RecordingDockerEnvironment(inner_env, recorder, snapshotter)
agent = RecordingAgent(model, environment, **agent_config)
# Continue through your existing runner's task execution and cleanup lifecycle.
```

This records actions, snapshots, and model-visible observations. To also record
model request/response bodies and budget reservations, supply a
`RecordingOpenRouterModel` as `model`. Its required configuration includes the
recorder, run ID, budget gateway, bucket/cell, expected provider, explicit
`max_tokens`, prompt/completion rates, and context ceiling. Set
`billable_output_ceiling_tokens` to a verified endpoint billing envelope when
reasoning can be billed beyond `max_tokens`. Provider order, fallback policy,
and maximum prices belong in `model_kwargs`; they are not inferred.

Create the gateway with **your explicit caps**, in integer microdollars
(`MICRO = 1_000_000` per USD). Its preserved default caps are historical study
settings. Ambiguous requests retain their reservation; a cap or accounting
violation writes `STOP_PAID_CALLS` beside the database. The estimates depend on
the supplied rates and provider behavior and are not a provider-side spending
limit.

## Output contract

```text
outputs/mini-swe/
├── blobs/<sha256>                  # deduplicated file and message bytes
└── runs/example/
    ├── events.jsonl               # ordered action/model-request events
    ├── snapshots.jsonl            # snapshot manifests
    ├── events_model_visible.jsonl # event-to-observation references
    ├── requests.jsonl             # responses/accounting, with the model recorder
    └── request_attempts.jsonl      # dispatch attempts, with the model recorder
```

Model transport can also produce `http/` and failure/retry sidecars. Request
Authorization headers are not serialized, but prompts, model outputs, tool
outputs, and captured files are retained as run data.

An action points to `before_snapshot` and `after_snapshot`. Each manifest has a
`snapshot_id`, Git `head`, `base_commit`, repository-relative `files` mapping,
absolute `tmp_files` mapping, and `unarchived_cache_paths`. File values are blob
hashes; a `null` repository-file value means deletion relative to the base.
Unchanged base files are not copied into every snapshot, so retain the matching
base repository and commit alongside the run.

`export_tracer_steps(run_dir)` maps action events to the field names in TRACER's
`Step` model. **Its `before_sha` and `after_sha` values are snapshot identifiers,
not Git commits.** These dictionaries are not the `cgt` decision ledger, and
must not be passed to a Git-based TRACER path as though they were Git history.
Reconstruct the referenced states before applying analyses that require files.
The connector itself does not detect ghost code or evaluate benchmark repairs.

## Capture limits

- States are observed initially and after each returned tool action. The next
  action uses the previous recorded state as its `before_snapshot`; independent
  background writes are not isolated.
- Files created and removed within one shell action are invisible. Commands
  returning a nonzero exit code are recorded, but an exception raised by the
  environment before returning can prevent the post-action record.
- Each captured file is limited to 10 MiB. Cache/build paths are listed without
  contents; failed captures are also listed as unarchived. `/tmp` capture is
  best effort and limited to the first 200 eligible paths per scan directory.
- `reconstruct()` rebuilds repository files from a trusted manifest and a base
  tree. It replaces its output directory and does not restore `/tmp`, Git
  metadata, executable modes, or a complete container image.

Use these limits when interpreting absence: an unrecorded artifact is not proof
that an agent never created or executed it.
