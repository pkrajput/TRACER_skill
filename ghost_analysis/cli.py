"""Portable entry points for static screening and a synthetic trajectory demo."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tokenize

from .helper_ast import analyze
from .structure import definitions, payloads, state_at


EXCLUDED_DIRS = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', 'build', 'dist'}


def source_files(path):
    if path.is_file():
        if path.suffix != '.py':
            raise ValueError('Choose a Python (.py) file or a directory.')
        yield path
        return
    if not path.is_dir():
        raise ValueError(f'Input does not exist: {path}')
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not Path(root, d).is_symlink())
        for name in sorted(files):
            candidate = Path(root, name)
            if candidate.suffix == '.py' and not candidate.is_symlink():
                yield candidate


def scan(path):
    records = []
    for file in source_files(path):
        try:
            with tokenize.open(file) as stream:
                source = stream.read()
            result = analyze(source)
            literal_records = payloads(source) if result['parse_error'] is None else []
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            result = {'parse_error': str(exc), 'effects': [], 'unknown_calls': []}
            literal_records = []
        writes = [e for e in result['effects'] if any(p.endswith('.py') for p in e['paths'])]
        records.append({
            'path': str(file),
            'source_writing_candidate': bool(writes),
            'history_support': 'not_checked',
            'task_redundancy': 'unknown',
            'embedded_definitions': sum(len(p['definitions']) for p in literal_records),
            **result,
        })
    return {'mode': 'static_screen', 'files_scanned': len(records),
            'source_writing_candidates': sum(r['source_writing_candidate'] for r in records),
            'parse_errors': sum(r['parse_error'] is not None for r in records),
            'files': records,
            'interpretation': 'Possible source writes only. History and deletion evidence are separate; no code is executed.'}


def correspondence(helper, before, after, final):
    """Compare complete literal definitions; matches are evidence, not execution proof."""
    before_units, after_units, final_units = map(definitions, (before, after, final))
    matches = []
    for literal in payloads(helper):
        for unit in literal['definitions']:
            for target in after_units:
                if unit['ast_sha256'] != target['ast_sha256']:
                    continue
                before_status = state_at(target, before_units)
                matches.append({'literal_line': literal['literal_line'],
                    'literal_roles': literal['roles'], 'target': target['qualified_name'],
                    'before_status': before_status,
                    'introduced_in_after': before_status not in {'current', 'ambiguous_duplicate_definition'},
                    'endpoint_status': state_at(target, final_units),
                    'ast_sha256': target['ast_sha256']})
    return matches


def write_report(report, output):
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect retained Python helpers without executing them.')
    commands = parser.add_subparsers(dest='command', required=True)
    screen = commands.add_parser('scan', help='Screen a Python file or directory for possible source writes')
    screen.add_argument('path', type=Path)
    screen.add_argument('--json', type=Path, metavar='OUTPUT', help='Write the complete report to a new JSON file')
    example = commands.add_parser('demo', help='Build and analyze a tiny synthetic recorded trajectory')
    example.add_argument('--out', type=Path, required=True, help='New directory for synthetic inputs and reports')
    compare = commands.add_parser('compare', help='Compare definitions embedded in a helper against product versions')
    for name in ('helper', 'before', 'after', 'final'):
        compare.add_argument('--' + name, type=Path, required=True)
    compare.add_argument('--json', type=Path, metavar='OUTPUT')
    args = parser.parse_args(argv)
    try:
        if args.command == 'scan':
            report = scan(args.path)
            write_report(report, args.json)
            print(f"Scanned {report['files_scanned']} Python files; {report['source_writing_candidates']} source-writing candidates; {report['parse_errors']} parse errors.")
            for record in report['files']:
                if record['source_writing_candidate']:
                    targets = sorted({p for effect in record['effects'] for p in effect['paths'] if p.endswith('.py')})
                    print(f"  {record['path']} -> {', '.join(targets)}")
                elif record['parse_error']:
                    print(f"  Unknown (parse/read error): {record['path']}")
            print('Candidates need history review. Task redundancy is unknown; no files are changed or executed.')
            return 0
        if args.command == 'compare':
            sources = []
            for path in (args.helper, args.before, args.after, args.final):
                with tokenize.open(path) as stream:
                    sources.append(stream.read())
            report = {'matches': correspondence(*sources), 'task_redundancy': 'unknown',
                      'interpretation': 'Exact AST correspondence only; confirm payload role and recorded invocation separately.'}
            write_report(report, args.json)
            print(json.dumps(report, indent=2))
            return 0
        from .demo import build_demo
        from .discover_helpers import main as discover
        build_demo(args.out)
        with contextlib.redirect_stdout(io.StringIO()):
            discover(['--archive', str(args.out / 'trajectory.zip'), '--batch', str(args.out / 'batch'),
                      '--out', str(args.out / 'discovery')])
        sources = args.out / 'source'
        matches = correspondence(*(sources.joinpath(name).read_text() for name in
                                  ['writer.py', 'before.py', 'after.py', 'final.py']))
        write_report({'synthetic': True, 'matches': matches, 'task_redundancy': 'unknown'}, args.out / 'correspondence.json')
        summary = json.loads((args.out / 'discovery/summary.json').read_text())
        print('Synthetic demo complete (no benchmark data or subject execution).')
        print(f"Static candidates: {summary['endpoint_static_writers']}; history-supported helpers: {summary['detected_files']}.")
        print('writer.py: recorded write with a target change; embedded implementation is superseded.')
        print('noop.py: possible writer, but its recorded invocation leaves the target unchanged.')
        print('data.py: source-writing text stored as data; no executable write found.')
        print('Task redundancy: unknown for every file. The demo includes no deletion evidence.')
        print(f'Reports: {args.out / "discovery"} and {args.out / "correspondence.json"}')
        return 0
    except (OSError, ValueError, SyntaxError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
