"""Local evidence preparation. Does not call models or execute analyzed code."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from security_ground_truth.runtime.git_history.query import GitHistoryView
from security_ground_truth.runtime.history.adapter import structural_index, normalize, build_view
from security_ground_truth.temporal_security.planner import plan
from security_ground_truth.temporal_security.history import agent_history
from security_ground_truth.temporal_security.rationale import build_rationale, public_rationale


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, sort_keys=True)
        stream.write('\n')


def load_targets(path):
    targets = json.loads(path.read_text())
    if not isinstance(targets, list):
        raise ValueError('Targets must be a JSON list')
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError('Each target must contain path and optional symbol')
        GitHistoryView._path(target.get('path'))
        if target.get('symbol') is not None and not isinstance(target['symbol'], str):
            raise ValueError('Target symbol must be a string')
    return targets


def normalized_alerts(args):
    from security_ground_truth.runtime.scanners import normalize_semgrep, normalize_codeql
    alerts = json.loads(args.alerts.read_text()) if args.alerts else []
    if not isinstance(alerts, list) or not all(isinstance(a, dict) for a in alerts):
        raise ValueError('Normalized alerts must be a JSON list of objects')
    for path, normalize_scanner in [(args.semgrep, normalize_semgrep), (args.codeql, normalize_codeql)]:
        if path:
            alerts.extend(normalize_scanner(json.loads(path.read_text()), args.source.resolve()))
    for alert in alerts:
        if not alert.get('alert_id'):
            identity = {k: alert.get(k) for k in ['tool', 'rule_id', 'path', 'line', 'end_line']}
            alert['alert_id'] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
    return alerts


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {'describe-change', 'prepare-history'}:
        from security_ground_truth.temporal_security.cli import main as history_main
        return history_main(argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog='Also supports describe-change and prepare-history. Use COMMAND --help.')
    commands = parser.add_subparsers(dest='command', required=True)
    index = commands.add_parser('index', help='Index a Python snapshot without importing it')
    index.add_argument('--source', type=Path, required=True)
    index.add_argument('--path', required=True, help='Repository-relative Python path')
    review = commands.add_parser('plan', help='Map a submitted patch and scanner findings to current symbols')
    review.add_argument('--source', type=Path, required=True)
    review.add_argument('--patch', type=Path, required=True)
    review.add_argument('--alerts', type=Path, help='Normalized alert JSON list')
    review.add_argument('--semgrep', type=Path, help='Semgrep JSON output')
    review.add_argument('--codeql', type=Path, help='CodeQL SARIF output')
    review.add_argument('--max-groups', type=int, default=12)
    trace = commands.add_parser('prepare-agent', help='Keep recorded edits and rationale in separate channels')
    trace.add_argument('--messages', type=Path, required=True, help='JSON message list or object with messages')
    trace.add_argument('--targets', type=Path, required=True)
    trace.add_argument('--source', type=Path, required=True, help='Current repository source')
    trace.add_argument('--cutoff-message', type=int)
    trace.add_argument('--rationale-only', action='store_true', help='No GumTree installation required')
    for cmd in [index, review, trace]:
        cmd.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'index':
            path = GitHistoryView._path(args.path)
            raw = args.source.read_bytes()
            result = {'path': path, 'source_sha256': hashlib.sha256(raw).hexdigest(),
                      **structural_index(raw.decode('utf-8'), path)}
            status = 0 if result['parse_status'] == 'parsed' else 2
        elif args.command == 'plan':
            if not args.source.is_dir() or args.max_groups < 1:
                raise ValueError('Source must be a directory and max-groups must be positive')
            result = plan(args.source.resolve(), args.patch.read_text(), normalized_alerts(args),
                          max_groups=args.max_groups)
            status = 0
        else:
            if not args.source.is_dir():
                raise ValueError('Current source must be a directory')
            targets = load_targets(args.targets)
            raw = args.messages.read_bytes()
            messages = json.loads(raw)
            if isinstance(messages, dict):
                messages = messages['messages']
            view = build_view(normalize(messages, hashlib.sha256(raw).hexdigest(),
                                        cutoff_message=args.cutoff_message), rationale=True, arm='B4')
            if args.rationale_only:
                temporal = {'status': 'not_requested', 'history_channel': 'recorded_agent'}
                rationale = build_rationale(view, targets, source_root=args.source.resolve())
            else:
                temporal, rationale = agent_history(view, targets, source_root=args.source.resolve())
            result = {'source_trace_sha256': view['source_trace_sha256'],
                      'cutoff_message': view['cutoff_message'],
                      'temporal_history': temporal, 'rationale': public_rationale(rationale)}
            status = 0
        write_new(args.output, result)
        print(json.dumps({'output': str(args.output), 'status': 'written', 'model_calls': 0}))
        return status
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(json.dumps({'status': 'error', 'type': type(error).__name__, 'message': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
