"""Pinned Semgrep/CodeQL baselines on isolated, oracle-free source exports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
from urllib.parse import unquote

from .common import run_logged, sha256, source_manifest, utcnow, write_json

DATA = Path(__file__).resolve().parents[1]


def unpack_source(archive: Path, destination: Path) -> dict:
    """Copy regular source files only; never extract links/devices or traversal."""
    destination.mkdir(parents=True, exist_ok=False)
    skipped, total = [], 0
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        if len(members) > 100_000:
            raise ValueError('Source archive member limit exceeded')
        for member in members:
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or '..' in rel.parts or '.git' in rel.parts:
                raise ValueError('Unsafe or evaluator Git archive member: ' + member.name)
            if member.isdir():
                continue
            if not member.isfile():
                skipped.append({'path': member.name, 'reason': 'nonregular_member'})
                continue
            total += member.size
            if member.size > 50_000_000 or total > 500_000_000:
                raise ValueError('Source archive size limit exceeded')
            path = destination.joinpath(*rel.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            with stream.extractfile(member) as source, path.open('xb') as target:
                target.write(source.read())
            path.chmod(0o444)
    return {'archive_sha256': sha256(archive), 'skipped': skipped, 'bytes': total}


def normalize_semgrep(document: dict, source: Path) -> list[dict]:
    alerts = []
    for row in document.get('results', []):
        path = row['path']
        if Path(path).is_absolute():
            try:
                path = str(Path(path).relative_to(source))
            except ValueError:
                continue
        alerts.append({'tool': 'semgrep', 'rule_id': row['check_id'], 'path': path,
                       'line': row['start']['line'], 'end_line': row['end']['line'],
                       'message': row.get('extra', {}).get('message'),
                       'severity': row.get('extra', {}).get('severity'),
                       'metadata': row.get('extra', {}).get('metadata', {}),
                       'flow': row.get('extra', {}).get('dataflow_trace'), 'gold_label': None})
    return alerts


def normalize_codeql(document: dict, source: Path) -> list[dict]:
    alerts = []
    for run in document.get('runs', []):
        rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
        for row in run.get('results', []):
            locations = row.get('locations', [])
            if not locations:
                continue
            loc = locations[0].get('physicalLocation', {})
            region = loc.get('region', {})
            path = unquote(loc.get('artifactLocation', {}).get('uri', ''))
            if path.startswith('file://'):
                path = path[7:]
            if Path(path).is_absolute():
                try:
                    path = str(Path(path).relative_to(source))
                except ValueError:
                    continue
            alerts.append({'tool': 'codeql', 'rule_id': row.get('ruleId'), 'path': path,
                           'line': region.get('startLine'), 'end_line': region.get('endLine', region.get('startLine')),
                           'message': row.get('message', {}).get('text'), 'severity': row.get('level'),
                           'metadata': rules.get(row.get('ruleId'), {}).get('properties', {}),
                           'flow': row.get('codeFlows', []), 'gold_label': None})
    return alerts


def scan(archive: Path, out: Path, config: dict) -> dict:
    if archive.parent.name != 'artifacts' or archive.parent.parent.name != 'func':
        raise ValueError('Only explicit functional-phase source exports admitted; hidden security tests excluded')
    state = json.loads((archive.parent / 'state_ready.json').read_text())
    if state.get('oracle_tests_in_source') is not False:
        raise ValueError('Oracle-free source assertion missing')
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'result.json').exists():
        old = json.loads((out / 'result.json').read_text())
        if old['source_archive_sha256'] != sha256(archive):
            raise ValueError('Source changed; use a new output directory')
        return old
    source = out / 'source'
    extraction = unpack_source(archive, source)
    write_json(out / 'source_extraction.json', extraction)
    write_json(out / 'source_manifest.json', source_manifest(source))
    write_json(out / 'scanner_config.json', config)
    rules = Path(config['semgrep']['rules_directory'])
    write_json(out / 'semgrep_rules_manifest.json', source_manifest(rules))
    ql = Path(config['codeql']['binary'])
    packs = ql.parent / 'qlpacks'
    write_json(out / 'codeql_packs_manifest.json', source_manifest(packs))
    extra_env = {'XDG_CONFIG_HOME': str(out / 'empty_config'), 'XDG_CACHE_HOME': str(out / 'cache'),
                 'SEMGREP_SETTINGS_FILE': str(out / 'semgrep_settings.yml')}
    (out / 'empty_config').mkdir(exist_ok=True)
    (out / 'cache').mkdir(exist_ok=True)
    semgrep_out = out / 'semgrep.json'
    s = config['semgrep']
    replacements = {'rules_directory': str(rules), 'output_json': str(semgrep_out), 'source_root': str(source)}
    command = [s['binary']] + [arg.format(**replacements) for arg in s['args']]
    semgrep = run_logged(command, out / 'commands/semgrep', cwd=out, timeout=900, env=extra_env)
    database = out / 'codeql-db'
    create = run_logged([str(ql), 'database', 'create', str(database), '--language=python',
                         '--build-mode=none', '--source-root=' + str(source), '--threads=2', '--ram=4096'],
                        out / 'commands/codeql_create', cwd=out, timeout=1200, env=extra_env)
    sarif = out / 'codeql.sarif'
    analyze = None
    if create['exit_code'] == 0:
        suite = packs / 'codeql/python-queries/1.3.4/codeql-suites/python-security-extended.qls'
        analyze = run_logged([str(ql), 'database', 'analyze', str(database), str(suite),
                              '--format=sarifv2.1.0', '--output=' + str(sarif), '--threads=2',
                              '--ram=4096', '--sarif-add-snippets', '--max-disk-cache=8192'],
                             out / 'commands/codeql_analyze', cwd=out, timeout=1800, env=extra_env)
    alerts, scanner_errors = [], {}
    if semgrep_out.exists():
        doc = json.loads(semgrep_out.read_text())
        alerts.extend(normalize_semgrep(doc, source))
        scanner_errors['semgrep'] = doc.get('errors', [])
    if sarif.exists():
        doc = json.loads(sarif.read_text())
        alerts.extend(normalize_codeql(doc, source))
        scanner_errors['codeql'] = [r.get('invocations', []) for r in doc.get('runs', [])]
    for alert in alerts:
        identity = {k: alert[k] for k in ['tool', 'rule_id', 'path', 'line', 'end_line']}
        alert['alert_id'] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
    write_json(out / 'alerts.json', alerts)
    write_json(out / 'scanner_diagnostics.json', scanner_errors)
    result = {'completed_utc': utcnow(), 'source_archive_sha256': sha256(archive),
              'source_manifest_sha256': sha256(out / 'source_manifest.json'),
              'source_directory': str(source), 'semgrep_status': semgrep['status'],
              'codeql_create_status': create['status'],
              'codeql_analyze_status': analyze['status'] if analyze else 'not_run',
              'semgrep_alerts': sum(a['tool'] == 'semgrep' for a in alerts),
              'codeql_alerts': sum(a['tool'] == 'codeql' for a in alerts),
              'security_labels_assigned': 0, 'status': 'baseline_outputs_require_coverage_review'}
    write_json(out / 'result.json', result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=DATA / 'experiment_setup/scanner_config.json')
    args = parser.parse_args()
    result = scan(args.source_archive.resolve(), args.output.resolve(), json.loads(args.config.read_text()))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
