"""Small process and provenance helpers; never inherits credential variables."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import tempfile


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Different workers may refresh shared status at the same instant. A fixed
    # .tmp filename races even when the final rename is atomic.
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix=path.name+'.', suffix='.tmp', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def clean_env(extra: dict | None = None) -> dict:
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'TZ') if key in os.environ}
    env.update({'LC_ALL': 'C.UTF-8', 'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2',
                'MKL_NUM_THREADS': '2', 'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
    env.update(extra or {})
    return env


def run_logged(argv: list[str], directory: Path, *, cwd: Path | None = None,
               timeout: int = 900, env: dict | None = None) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    metadata = {'argv': argv, 'cwd': str(cwd) if cwd else None, 'started_utc': utcnow(),
                'timeout_seconds': timeout, 'status': 'running'}
    write_json(directory / 'command.json', metadata)
    start = time.monotonic()
    with (directory / 'stdout.log').open('wb') as out, (directory / 'stderr.log').open('wb') as err:
        process = subprocess.Popen(argv, cwd=cwd, env=clean_env(env), stdout=out, stderr=err,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
            status = 'completed' if code == 0 else 'command_failed'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            status = 'timeout'
    metadata.update({'status': status, 'exit_code': code, 'finished_utc': utcnow(),
                     'elapsed_seconds': time.monotonic() - start,
                     'stdout_sha256': sha256(directory / 'stdout.log'),
                     'stderr_sha256': sha256(directory / 'stderr.log')})
    write_json(directory / 'command.json', metadata)
    return metadata


def source_manifest(root: Path) -> dict:
    files, excluded = [], []
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if '.git' in relative.parts:
            continue
        if path.is_symlink():
            excluded.append(str(relative))
        elif path.is_file():
            files.append({'path': str(relative), 'sha256': sha256(path), 'bytes': path.stat().st_size})
    encoded = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return {'root': str(root), 'files': files, 'tree_sha256': hashlib.sha256(encoded).hexdigest(),
            'symlinks_not_followed': excluded}
