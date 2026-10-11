# Contributing

Keep the recorder, recording connectors, and analysis modules independently
usable. Small synthetic examples make changes easier to inspect and validate
without distributing recorded sessions or starting paid model runs.

## Development setup

From the repository root, with Python 3.10+ and Git installed:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e './tracer[dev,panel,sync,languages]' -e ./tracer/query_layer
```

The analysis and offline connector smoke check use only the standard library.
The TRACER test suite uses pytest and the installed optional extras. Sync crypto
tests also use `ssh-keygen`; hosted sync integration tests require a separately
configured emulator and are skipped without it. Embedding integration requires
the separate embeddings extra and model resources.

## Run checks

```sh
python -m unittest discover -s ghost_analysis/tests -v
python -m connectors.mini_swe_agent.smoke
python -m pytest tracer/tests tracer/query_layer/tests
python tracer/examples/quickstart.py
```

To try the analysis demo again, choose an unused output directory:

```sh
python -m ghost_analysis demo --out outputs/my-demo
```

These commands validate implementation behavior and the documented examples.
They do not run the research agents or establish new benchmark results.

## Reporting and changing behavior

For analysis bugs, include a minimal source example, the command, expected
behavior, and actual report. For recording bugs, include the relevant steps and
Git layout with private content removed. Include Python and operating-system
versions where they affect reproduction.

Preserve the difference between a static candidate, a history-supported helper,
and task-oracle redundancy. Keep missing or unparsable evidence explicit. New
detector patterns should have positive and negative examples; changes to evidence
handling should cover the ambiguity or missing-data case that motivated them.

Update the relevant component guide when commands or input formats change.
Keep large archives, environments, generated reports, and credentials outside
commits. Preserve source provenance and third-party notices.
