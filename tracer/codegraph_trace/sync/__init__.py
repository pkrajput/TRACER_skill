"""TRACER Sync — zero-knowledge, end-to-end-encrypted team sync for trace data.

The sync layer lets a team ("entity") share the full development, prompt and
reasoning cycle that TRACER records (``.codegraph-trace/`` plus artifacts),
through a Firebase-hosted relay that only ever sees encrypted blobs.

Modules:
  crypto     Password hashing (scrypt) and hybrid encryption (age, SSH recipients).
  sshkeys    Locate / generate / load SSH ed25519 keypairs.
  state      Local ``~/.tracer/`` config and session storage.
  payload    Build and extract the tar.gz sync archive.
  transport  HTTP client for the Firebase Cloud Functions API.
  client     High-level operations: entity, login, keys, push, pull, status.
  cli        The ``tracer`` command-line interface.
"""

__all__ = ["crypto", "sshkeys", "state", "payload", "transport", "client"]
