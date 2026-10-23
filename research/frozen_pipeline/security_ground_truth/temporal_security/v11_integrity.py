"""Deterministic file sets and external-input identities for the v11 pilot."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from security_ground_truth.runtime.common import sha256
from security_ground_truth.runtime.investigation import CODEQL


CODE_DIRECTORIES = ('temporal_security', 'repair_check', 'runtime')
EVALUATION_INPUTS = (
    'task.json',
    'logs_handler.json',
    'image_identity.json',
    'agent_effective.patch',
    'security_tests.patch',
    'expected_masked_files.json',
    'runs/agent/func/control/run.json',
    'runs/agent/sec/control/run.json',
    'runs/agent/func/artifacts/result.json',
    'runs/agent/func/artifacts/test.stdout',
    'runs/agent/func/artifacts/test.stderr',
    'runs/agent/func/logs/copy_output/exit.json',
    'runs/agent/sec/artifacts/result.json',
    'runs/agent/sec/artifacts/test.stdout',
    'runs/agent/sec/artifacts/test.stderr',
    'runs/agent/sec/logs/copy_output/exit.json',
)

PRIOR_CELL_FIXED = (
    'candidate.patch',
    'unvalidated_candidate.patch',
    'input.json',
    'result.json',
    'trajectory.json',
    'hypotheses.json',
    'assessments.json',
    'check_evidence.json',
    'edit_note.json',
    'rationale_exposure.json',
    'complete.json',
    'evaluation/evaluation.json',
    'evaluation/source_provenance.json',
    'evaluation/func/artifacts/result.json',
    'evaluation/func/artifacts/test.stdout',
    'evaluation/func/artifacts/test.stderr',
    'evaluation/func/artifacts/source_identity.json',
    'evaluation/func/artifacts/state_ready.json',
    'evaluation/func/artifacts/applied_patches.json',
    'evaluation/sec/artifacts/result.json',
    'evaluation/sec/artifacts/test.stdout',
    'evaluation/sec/artifacts/test.stderr',
    'evaluation/sec/artifacts/source_identity.json',
    'evaluation/sec/artifacts/state_ready.json',
    'evaluation/sec/artifacts/applied_patches.json',
)
PRIOR_CELL_INVENTORIES = ('checks/*/feedback.json', 'functional/*/feedback.json')


def qualified_code_paths(repo):
    """Return the exact locally qualified code/dependency file set."""
    repo = Path(repo)
    return sorted(
        path
        for directory in CODE_DIRECTORIES
        for path in (repo / 'security_ground_truth' / directory).rglob('*')
        if path.is_file()
        and (path.suffix == '.py' or path.name == 'gumtree_dependencies.json')
    )


def qualified_code_hashes(repo):
    repo = Path(repo)
    return {str(path.relative_to(repo)): sha256(path)
            for path in qualified_code_paths(repo)}


def execution_code_audit(manifest, module_file):
    """Compare the code beside the executing module with the prepared frozen tree."""
    repo = Path(module_file).resolve().parents[2]
    actual = qualified_code_hashes(repo)
    prefix = 'frozen_code/'
    expected = {name[len(prefix):]: digest
                for name, digest in manifest.get('frozen_sha256', {}).items()
                if name.startswith(prefix)}
    changed = [name for name in sorted(set(actual) | set(expected))
               if actual.get(name) != expected.get(name)]
    return {'execution_repo': str(repo), 'files': len(actual),
            'expected_files': len(expected), 'changed': changed,
            'matched': not changed and bool(expected)}


def _stream_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(4 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def tree_snapshot(root):
    """Return a content, path, type and mode identity for an input tree."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError('Missing frozen input tree: ' + str(root))
    rows = []
    total = 0
    files = 0
    links = 0
    for path in sorted(root.rglob('*')):
        name = str(path.relative_to(root))
        if path.is_symlink():
            rows.append(('symlink', name, os.readlink(path)))
            links += 1
        elif path.is_file():
            stat = path.stat()
            size = stat.st_size
            rows.append(('file', name, _stream_sha256(path), size, stat.st_mode & 0o777))
            total += size
            files += 1
        elif not path.is_dir():
            raise ValueError('Unsupported entry in frozen input tree: ' + str(path))
    return {
        'root': str(root),
        'files': files,
        'symlinks': links,
        'bytes': total,
        'tree_sha256': hashlib.sha256(
            json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode()
        ).hexdigest(),
    }


def codeql_runtime_snapshot():
    """Identify the launcher, tools and complete qlpack search path used by queries."""
    value = tree_snapshot(CODEQL.parent)
    value['launcher'] = str(CODEQL)
    value['launcher_sha256'] = sha256(CODEQL)
    return value


def prior_material_snapshot(version, base, case_keys, arms=('C0', 'C3')):
    """Record both presence and content of every prior artifact the report can read."""
    base = Path(base)
    fixed = {}
    inventories = {}
    for key in case_keys:
        for arm in arms:
            cell = base / 'cells' / key / arm
            for suffix in PRIOR_CELL_FIXED:
                path = cell / suffix
                name = str(path.relative_to(base))
                fixed[name] = sha256(path) if path.is_file() else None
            for pattern in PRIOR_CELL_INVENTORIES:
                inventory = 'cells/' + key + '/' + arm + '/' + pattern
                inventories[inventory] = {
                    str(path.relative_to(base)): sha256(path)
                    for path in sorted(cell.glob(pattern)) if path.is_file()
                }
    for name in [
            'manifest.json', 'authorization.json', 'cases.json', 'config.json',
            'selector.json', 'status.json',
            'report/' + version.upper() + '_DEV_COMPARISON.json',
            'report/' + version.upper() + '_DEV_COMPARISON.md',
            'report/MECHANISM_REVIEW.json', 'report/DIAGNOSTIC_FINDINGS.json']:
        path = base / name
        fixed[name] = sha256(path) if path.is_file() else None
    return {
        'schema': 'v11-prior-report-material-v1',
        'version': version,
        'case_keys': list(case_keys),
        'arms': list(arms),
        'fixed': fixed,
        'inventories': inventories,
    }


def prior_material_changes(recorded, version, base, case_keys, arms=('C0', 'C3')):
    current = prior_material_snapshot(version, base, case_keys, arms)
    changed = []
    for field in ['schema', 'version', 'case_keys', 'arms']:
        if recorded.get(field) != current[field]:
            changed.append('<metadata:' + field + '>')
    recorded_fixed = recorded.get('fixed', {})
    for name in sorted(set(recorded_fixed) | set(current['fixed'])):
        if recorded_fixed.get(name, '<missing>') != current['fixed'].get(name, '<missing>'):
            changed.append(name)
    recorded_inventories = recorded.get('inventories', {})
    for pattern in sorted(set(recorded_inventories) | set(current['inventories'])):
        if recorded_inventories.get(pattern, '<missing>') != current['inventories'].get(
                pattern, '<missing>'):
            changed.append(pattern)
    return changed


def _validated_source_tree(baseline):
    baseline = Path(baseline)
    manifest_path = baseline / 'source_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    rows = manifest.get('files')
    if not isinstance(rows, list):
        raise ValueError('Baseline source manifest has no file list')
    expected = {}
    for row in rows:
        name = row.get('path') if isinstance(row, dict) else None
        if (not isinstance(name, str) or not name
                or Path(name).is_absolute() or '..' in Path(name).parts
                or not isinstance(row.get('sha256'), str)
                or type(row.get('bytes')) is not int):
            raise ValueError('Invalid baseline source manifest row')
        if name in expected:
            raise ValueError('Duplicate baseline source manifest path: ' + name)
        expected[name] = (row['sha256'], row['bytes'])
    source = baseline / 'source'
    actual = {str(path.relative_to(source)) for path in source.rglob('*')
              if path.is_file() or path.is_symlink()}
    if actual != set(expected):
        raise ValueError('Baseline source tree path set differs from its manifest')
    identity = []
    for name, (digest, size) in sorted(expected.items()):
        path = source / name
        if path.is_symlink() or path.stat().st_size != size or sha256(path) != digest:
            raise ValueError('Baseline source differs from its manifest: ' + name)
        identity.append((name, digest, size))
    return {
        'source_manifest_sha256': sha256(manifest_path),
        'source_files': len(identity),
        'source_tree_sha256': hashlib.sha256(
            json.dumps(identity, separators=(',', ':')).encode()).hexdigest(),
    }


def case_external_snapshot(case):
    """Hash source identities and host files used by repair/evaluation/reporting."""
    case_path = Path(case['case_path'])
    files = {}
    for name in EVALUATION_INPUTS:
        path = case_path / name
        if not path.is_file():
            raise ValueError('Missing official evaluation input: ' + str(path))
        files[name] = sha256(path)
    identity = json.loads((case_path / 'image_identity.json').read_text())
    image_id = identity.get('image_id')
    if not isinstance(image_id, str) or not image_id.startswith('sha256:'):
        raise ValueError('Official evaluation image is not digest-pinned')
    return {
        **_validated_source_tree(case['baseline']),
        'alerts_sha256': sha256(Path(case['baseline']) / 'alerts.json'),
        'codeql_database': tree_snapshot(Path(case['baseline']) / 'codeql-db'),
        'evaluation_files_sha256': files,
        'image_id': image_id,
    }


def validate_case_external_snapshot(case):
    recorded = case.get('v11_external_input_snapshot')
    if not isinstance(recorded, dict) or case_external_snapshot(case) != recorded:
        raise ValueError('Frozen external repair/evaluation inputs changed: '
                         + case.get('case_key', '<unknown>'))
