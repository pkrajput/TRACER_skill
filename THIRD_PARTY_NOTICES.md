# Third-party components and evidence

The TRACER code in this release uses the repository's Apache-2.0 license.
Third-party software and input datasets retain their own terms.

- GumTree 3.0.0 supplies the AST matcher. Its core is LGPL-3.0. The installer
  downloads the pinned Java dependencies from Maven Central and verifies their
  hashes. Their licenses remain upstream. JAR files are not vendored here.
- Python's standard-library AST, tokenizer, and other modules retain the Python
  Software Foundation license. Git and the JDK are separately installed tools.
- Semgrep and CodeQL are separately installed scanners. No scanner binary,
  commercial entitlement, or third-party rule pack is redistributed here.
- SusVibes supplies the published repository tasks, coding trajectories, and
  evaluation protocol. This repository distributes our derived result records
  and source identities. It does not relicense the upstream repositories or
  include their entire source trees or Docker images.
- `jsonschema` is an optional test dependency under its upstream MIT license.

The Python security pipeline builds its symbol index using Python's standard
library. No external symbol-indexing server is required.
