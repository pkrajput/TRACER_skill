"""Build / extract the sync payload archive.

The payload is a deterministic tar.gz of the configured sync paths (default:
``.codegraph-trace/`` — trace.db, snapshots, embeddings — plus ``artifacts/``)
relative to the repo root, with a ``tracer-manifest.json`` describing what was
packed. The archive is built *locally*, encrypted *locally*, and only the
ciphertext ever leaves the machine.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path
from typing import Iterable, Optional

MANIFEST_NAME = "tracer-manifest.json"


class PayloadError(Exception):
    pass


def build_archive(
    repo_root: Path,
    sync_paths: Iterable[str],
    *,
    pushed_by: str,
    entity: str,
    message: str = "",
) -> bytes:
    """Pack ``sync_paths`` (relative to ``repo_root``) into a tar.gz in memory."""
    repo_root = Path(repo_root).resolve()
    included: list[str] = []
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in sync_paths:
            target = (repo_root / rel).resolve()
            if not str(target).startswith(str(repo_root)):
                raise PayloadError(f"sync path escapes the repo root: {rel}")
            if not target.exists():
                continue
            tar.add(target, arcname=rel, recursive=True)
            included.append(rel)
        if not included:
            raise PayloadError(
                "nothing to sync: none of the configured paths exist under "
                f"{repo_root} (looked for: {', '.join(sync_paths)})"
            )
        manifest = {
            "format": "tracer-sync/1",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pushed_by": pushed_by,
            "entity": entity,
            "message": message,
            "paths": included,
        }
        data = json.dumps(manifest, indent=2).encode()
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(data)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def read_manifest(archive: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.getmember(MANIFEST_NAME)
        fh = tar.extractfile(member)
        if fh is None:
            raise PayloadError("manifest missing from archive")
        return json.loads(fh.read())


def read_member(archive: bytes, name: str) -> Optional[bytes]:
    """Return one member's bytes from an archive, or None when it is not packed.

    Used to read a single small file (the review ledger) out of a decrypted payload
    without touching the working tree.
    """
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        try:
            member = tar.getmember(name)
        except KeyError:
            return None
        fh = tar.extractfile(member)
        return fh.read() if fh is not None else None


def extract_archive(archive: bytes, repo_root: Path) -> list[str]:
    """Extract a pulled archive over ``repo_root``; returns the restored paths.

    Existing files under the synced paths are replaced (the pulled state wins);
    everything outside the archive's paths is untouched.
    """
    repo_root = Path(repo_root).resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise PayloadError(f"unsafe path in archive: {member.name}")
        manifest_member = tar.getmember(MANIFEST_NAME)
        fh = tar.extractfile(manifest_member)
        manifest = json.loads(fh.read()) if fh else {}
        members = [m for m in tar.getmembers() if m.name != MANIFEST_NAME]
        # Remove existing regular files first: read-only files (e.g. .git
        # object files, mode 0444) cannot be opened for overwrite by tar.
        for member in members:
            if member.isdir():
                continue
            target = repo_root / member.name
            try:
                if target.is_file() or target.is_symlink():
                    target.unlink()
            except OSError:
                pass  # fall through; extraction reports anything fatal
        try:
            tar.extractall(repo_root, members=members, filter="data")
        except OSError as exc:
            raise PayloadError(f"could not write pulled files under {repo_root}: {exc}") from exc
    return list(manifest.get("paths", []))
