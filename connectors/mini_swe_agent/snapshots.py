"""Content-addressed snapshots of a repository inside a Docker container.

The snapshotter runs its own ``docker exec`` calls (invisible to the model's
conversation) and never touches the model-visible filesystem: no marker files,
no extra git commits inside the container. Changed-file discovery uses
``git status`` against the task's base commit; scratch files in /tmp are
captured best-effort by mtime. A file created AND removed within one shell
action cannot be observed by this post-action snapshotter; such within-action
churn is recorded as unobserved (see study config).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# New ignored files matching these patterns are treated as dependency/cache/build
# products: they are listed (path only) but their content is not archived.
CACHE_PATTERNS = re.compile(
    r"(__pycache__|\.pyc$|\.pyo$|\.egg-info|\.pytest_cache|\.tox/|\.mypy_cache|"
    r"node_modules/|\.cache/|\.eggs/|build/|dist/|\.coverage)"
)
MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # per file


class BlobStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        h = hashlib.sha256(data).hexdigest()
        p = self.root / h
        if not p.exists():
            # unique tmp name: concurrent writers of the same content must
            # not race on one tmp path (Phase 2 runs 3 runner processes)
            tmp = self.root / f"{h}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            tmp.write_bytes(data)
            try:
                tmp.rename(p)  # atomic on POSIX; last writer wins, same bytes
            except OSError:
                if not p.exists():
                    raise
                tmp.unlink(missing_ok=True)
        return h

    def get(self, sha: str) -> bytes:
        return (self.root / sha).read_bytes()

    def has(self, sha: str) -> bool:
        return (self.root / sha).exists()


@dataclass
class SnapshotManifest:
    snapshot_id: str
    head: str
    base_commit: str
    files: dict  # repo-relative path -> blob sha256 | None (None = deleted vs base)
    tmp_files: dict  # absolute path -> blob sha256 (best-effort scratch outside repo)
    unarchived_cache_paths: list
    label: str
    created_at: str

    def to_json(self) -> dict:
        return self.__dict__.copy()


def _canonical_id(head: str, base: str, files: dict, tmp_files: dict) -> str:
    payload = json.dumps(
        {"head": head, "base": base, "files": files, "tmp": tmp_files},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class ContainerSnapshotter:
    """Snapshot /testbed (or any git repo dir) inside a running container."""

    def __init__(self, container_id: str, repo_dir: str, base_commit: str,
                 blob_store: BlobStore, docker: str = "docker",
                 tmp_scan_dirs: tuple[str, ...] = ("/tmp",)):
        self.container_id = container_id
        self.repo_dir = repo_dir
        self.base_commit = base_commit
        self.blobs = blob_store
        self.docker = docker
        self.tmp_scan_dirs = tmp_scan_dirs
        self.start_stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        self.last_snapshot: SnapshotManifest | None = None

    # ------------------------------------------------------------ docker io
    def _exec(self, argv: list[str], binary: bool = False, timeout: int = 120):
        cmd = [self.docker, "exec", self.container_id] + argv
        res = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = res.stdout if binary else res.stdout.decode("utf-8", "replace")
        return res.returncode, out

    # ------------------------------------------------------------- discovery
    def _changed_paths(self) -> tuple[dict, list]:
        """(path -> 'present'|'deleted', cache_paths). Diff is vs base_commit,
        so it stays correct even if the agent makes git commits."""
        rc, diff_out = self._exec(
            ["git", "-C", self.repo_dir, "-c", "core.quotePath=false",
             "diff", "--name-status", self.base_commit])
        states: dict[str, str] = {}
        if rc == 0:
            for line in diff_out.splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                st = parts[0]
                if st.startswith("R") and len(parts) == 3:  # rename: old del, new add
                    states[parts[1]] = "deleted"
                    states[parts[2]] = "present"
                elif st.startswith("D"):
                    states[parts[1]] = "deleted"
                else:
                    states[parts[1]] = "present"
        # untracked (non-ignored) + ignored, via status
        rc, st_out = self._exec(
            ["git", "-C", self.repo_dir, "-c", "core.quotePath=false",
             "status", "--porcelain=v1", "-uall", "--ignored=matching"])
        cache_paths: list[str] = []
        ignored_dirs: list[str] = []
        if rc == 0:
            for line in st_out.splitlines():
                if len(line) < 4:
                    continue
                code, path = line[:2], line[3:].strip()
                if " -> " in path:
                    path = path.split(" -> ")[-1]
                if path.endswith("/"):
                    # ignored/untracked directory reported as one entry: expand it
                    if CACHE_PATTERNS.search(path):
                        cache_paths.append(path)
                    else:
                        ignored_dirs.append(path.rstrip("/"))
                    continue
                if code == "!!":
                    if CACHE_PATTERNS.search(path):
                        cache_paths.append(path)
                    else:
                        states[path] = "present"  # agent scratch in ignored location
                elif code.strip() in ("D",):
                    states[path] = "deleted"
                else:
                    states[path] = "present"
        for d in ignored_dirs:
            rc, out = self._exec(
                ["find", f"{self.repo_dir}/{d}", "-type", "f", "-size", "-10M"])
            if rc != 0:
                continue
            prefix = self.repo_dir.rstrip("/") + "/"
            for p in out.splitlines():
                if not p.startswith(prefix):
                    continue
                rel = p[len(prefix):]
                if CACHE_PATTERNS.search(rel):
                    cache_paths.append(rel)
                else:
                    states[rel] = "present"
        return states, cache_paths

    def _capture_files(self, root: str, rel_paths: list[str]) -> dict:
        """Tar the given paths out of the container, return path -> blob sha."""
        result: dict[str, str] = {}
        if not rel_paths:
            return result
        # chunk to keep argv bounded
        for i in range(0, len(rel_paths), 200):
            chunk = rel_paths[i:i + 200]
            rc, data = self._exec(
                ["tar", "-C", root, "-cf", "-", "--ignore-failed-read", "--"]
                + chunk, binary=True, timeout=300)
            if not data:
                continue
            try:
                tf = tarfile.open(fileobj=io.BytesIO(data))
            except tarfile.TarError:
                continue
            for member in tf.getmembers():
                if not member.isfile() or member.size > MAX_CAPTURE_BYTES:
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                name = member.name.lstrip("./")
                result[name] = self.blobs.put(f.read())
        return result

    def _scan_tmp(self) -> dict:
        found: dict[str, str] = {}
        for d in self.tmp_scan_dirs:
            rc, out = self._exec(
                ["find", d, "-xdev", "-type", "f", "-newermt", self.start_stamp,
                 "-size", "-10M"])
            if rc != 0:
                continue
            paths = [p for p in out.splitlines()
                     if p and not CACHE_PATTERNS.search(p)][:200]
            if not paths:
                continue
            rels = [p.lstrip("/") for p in paths]
            captured = self._capture_files("/", rels)
            for rel, sha in captured.items():
                found["/" + rel] = sha
        return found

    # -------------------------------------------------------------- snapshot
    def snapshot(self, label: str = "") -> SnapshotManifest:
        rc, head = self._exec(["git", "-C", self.repo_dir, "rev-parse", "HEAD"])
        head = head.strip() if rc == 0 else "UNKNOWN"
        states, cache_paths = self._changed_paths()
        present = [p for p, s in states.items() if s == "present"]
        captured = self._capture_files(self.repo_dir, present)
        files: dict[str, str | None] = {}
        for p, s in states.items():
            if s == "deleted":
                files[p] = None
            elif p in captured:
                files[p] = captured[p]
            # present but capture failed (races, size) -> omit, but note below
        missing = [p for p in present if p not in captured]
        tmp_files = self._scan_tmp()
        sid = _canonical_id(head, self.base_commit, files, tmp_files)
        man = SnapshotManifest(
            snapshot_id=sid, head=head, base_commit=self.base_commit,
            files=files, tmp_files=tmp_files,
            unarchived_cache_paths=sorted(cache_paths + missing),
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.last_snapshot = man
        return man


def reconstruct(manifest: dict, base_tree: Path, out_tree: Path,
                blobs: BlobStore) -> None:
    """Rebuild the working tree state: copy base_tree, apply manifest deltas."""
    import shutil
    if out_tree.exists():
        shutil.rmtree(out_tree)
    shutil.copytree(base_tree, out_tree, symlinks=True,
                    ignore=shutil.ignore_patterns(".git"))
    for rel, sha in manifest["files"].items():
        target = out_tree / rel
        if sha is None:
            if target.exists():
                target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blobs.get(sha))
