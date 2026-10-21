"""Deterministic, label-blind review plan anchored in the submitted code change.

Input is the generated patch against the masked starting tree, NEVER SusVibes'
task_patch/golden_patch/security_patch. AST relations are syntactic candidates,
not a claim of sound call-graph or data-flow analysis. Scanner code-flow
locations remain separately attributed to the scanner.
"""
from __future__ import annotations

import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import unquote
from security_ground_truth.runtime.alert_identity import unique_alerts

HUNK = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
BOUNDARY = re.compile(r'header|redirect|url|path|auth|session|token|password|secret|sql|command|deserial|valid|escape|saniti|cookie', re.I)
SINK = re.compile(r'(?:^|\.)(?:exec|eval|execute|executemany|Popen|run|loads?|open|render|redirect|send|request|set_header|add_header)$')


def production(path):
    p = PurePosixPath(path)
    return (bool(path) and not p.is_absolute() and '..' not in p.parts and p.suffix == '.py'
            and not any(x.lower() in {'test', 'tests', 'testing', 'docs', 'doc', 'examples', 'example', '.git'} for x in p.parts)
            and not p.name.startswith('test_') and not p.name.endswith('_test.py'))


def _safe_path(value, source=None):
    if not isinstance(value, str):
        return None
    value = unquote(value)
    if value.startswith('file://'):
        value = value[7:]
    if source and value.startswith(str(source.resolve()) + '/'):
        value = value[len(str(source.resolve())) + 1:]
    if value.startswith('./'):
        value = value[2:]
    p = PurePosixPath(value)
    return str(p) if not p.is_absolute() and '..' not in p.parts and value else None


def patch_lines(patch_text):
    """New-tree edited lines plus explicitly distinguished deletion anchors."""
    result = defaultdict(lambda: {'added_lines': set(), 'deletion_anchors': set()})
    path = None
    line = None
    in_hunk = False
    for text in patch_text.splitlines():
        if text.startswith('diff --git '):
            path = None; line = None; in_hunk = False
        elif text.startswith('+++ ') and not in_hunk:
            raw = text[4:].split('\t', 1)[0]
            if raw.startswith('"'):
                try:
                    raw = json.loads(raw)
                except ValueError:
                    raw = ''
            path = _safe_path(raw[2:] if raw.startswith('b/') else raw)
            if not path or not production(path):
                path = None
        elif text.startswith('@@ '):
            match = HUNK.match(text)
            line = int(match.group(1)) if match else None
            in_hunk = bool(match)
        elif in_hunk and line is not None:
            if text.startswith('+'):
                if path:
                    result[path]['added_lines'].add(max(1, line))
                line += 1
            elif text.startswith('-'):
                if path:
                    result[path]['deletion_anchors'].add(max(1, line))
            elif text.startswith(' '):
                line += 1
    return {path: {k: sorted(v) for k, v in values.items()} for path, values in sorted(result.items())}


def _symbols(text, path):
    """Function, class and module boundaries; duplicate definitions stay distinct."""
    tree = ast.parse(text)
    rows = []

    def walk(node, parents=()):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = '.'.join((*parents, child.name))
                start = min([child.lineno] + [d.lineno for d in getattr(child, 'decorator_list', [])])
                row = {'path': path, 'symbol': name, 'kind': type(child).__name__,
                       'start_line': start, 'end_line': child.end_lineno,
                       'calls': [], 'guards': []}
                # Nested functions/classes get their own features, not their parent's.
                def features(current):
                    if current is not child and isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        return
                    if isinstance(current, ast.Call):
                        row['calls'].append({'line': current.lineno, 'callee': ast.unparse(current.func)[:300]})
                    if isinstance(current, (ast.If, ast.Assert, ast.While)):
                        row['guards'].append({'line': current.lineno, 'condition': ast.unparse(current.test)[:500]})
                    for nested in ast.iter_child_nodes(current):
                        features(nested)
                features(child)
                rows.append(row)
                walk(child, (*parents, child.name))
            else:
                walk(child, parents)
    walk(tree)
    return rows


def _enclosing(symbols, line):
    matches = [s for s in symbols if s['start_line'] <= line <= s['end_line']]
    return min(matches, key=lambda s: s['end_line'] - s['start_line']) if matches else None


def _id(path, symbol, line):
    return hashlib.sha256(f'{path}:{symbol}:{line}'.encode()).hexdigest()[:20]


def _locations(alert, source):
    result = []
    path = _safe_path(alert.get('path'), source)
    line = alert.get('line')
    if path and isinstance(line, int) and line > 0:
        result.append({'path': path, 'line': line, 'kind': 'scanner_primary_location'})
    flow = alert.get('flow') or []
    if not isinstance(flow, list):
        return result
    for cf in flow:
        for tf in cf.get('threadFlows', []):
            for loc in tf.get('locations', []):
                physical = loc.get('location', {}).get('physicalLocation', {})
                p = _safe_path(physical.get('artifactLocation', {}).get('uri'), source)
                ln = physical.get('region', {}).get('startLine')
                if p and isinstance(ln, int) and ln > 0:
                    item = {'path': p, 'line': ln, 'kind': 'scanner_flow_location'}
                    if item not in result:
                        result.append(item)
    return result


def plan(source: Path, patch_text: str, alerts: list, *, max_groups: int = 12,
         max_context_chars: int = 42000) -> dict:
    """Return a complete inventory and a bounded review context; no labels read.

    selected_groups is prompt context. scanner_ledger and changed_symbols are
    audit/retrieval inventories; consumers should not truncate them silently or
    dump a whole-repository ledger into an LLM prompt. No candidate is dropped
    merely because stock scanners have no rule for it.
    """
    if max_groups < 1 or max_context_chars < 1000:
        raise ValueError('Positive group budget and at least 1000 context characters required')
    source = source.resolve()
    changed = patch_lines(patch_text)
    parsed, errors, files = {}, [], {}

    def load(path):
        if path in parsed:
            return parsed[path]
        candidate = (source / path).resolve()
        if not production(path) or not candidate.is_relative_to(source) or not candidate.is_file():
            errors.append({'path': path, 'status': 'missing_or_excluded_source'})
            parsed[path] = []
            return []
        if candidate.stat().st_size > 2_000_000:
            errors.append({'path': path, 'status': 'source_over_2mb'})
            parsed[path] = []
            return []
        text = candidate.read_text(errors='replace')
        files[path] = text
        try:
            parsed[path] = _symbols(text, path)
        except (SyntaxError, RecursionError) as exc:
            errors.append({'path': path, 'status': 'ast_unavailable', 'error': type(exc).__name__})
            parsed[path] = []
        return parsed[path]

    groups = {}

    def add(path, symbol, line):
        key = _id(path, symbol['symbol'] if symbol else '<module>', symbol['start_line'] if symbol else 1)
        if key not in groups:
            groups[key] = {'group_id': key, 'path': path,
                           'symbol': symbol['symbol'] if symbol else '<module>',
                           'kind': symbol['kind'] if symbol else 'ModuleFragment',
                           'start_line': symbol['start_line'] if symbol else 1,
                           'end_line': symbol['end_line'] if symbol else len(files.get(path,'').splitlines()),
                           'calls': list(symbol['calls']) if symbol else [],
                           'guards': list(symbol['guards']) if symbol else [],
                           'changed_lines': [], 'deletion_anchors': [], 'reasons': [],
                           'alert_ids': [], 'related_group_ids': []}
        return groups[key]

    for path, edit in changed.items():
        symbols = load(path)
        if path not in files:
            continue
        source_lines = files[path].splitlines()
        for key, target in [('added_lines', 'changed_lines'), ('deletion_anchors', 'deletion_anchors')]:
            for line in edit[key]:
                if key == 'added_lines' and (line > len(source_lines) or not source_lines[line - 1].strip() or source_lines[line - 1].lstrip().startswith('#')):
                    continue
                row = add(path, _enclosing(symbols, line), line)
                row[target].append(line)
                if 'submitted_patch_change' not in row['reasons']:
                    row['reasons'].append('submitted_patch_change')

    # Changed-line ownership is anchored in the actual submitted patch, not
    # whichever fragments happened to survive in the archived action history.
    changed_ids = set(groups)
    changed_by_name = defaultdict(list)
    for row in groups.values():
        if row['symbol'] != '<module>':
            changed_by_name[row['symbol'].split('.')[-1]].append(row)

    # One-hop local call relations are explicitly syntactic; never claim a
    # method-name match proves dispatch, reachability or exploitation.
    for path in sorted(changed):
        for sym in load(path):
            matches = []
            for call in sym['calls']:
                matches.extend(changed_by_name.get(call['callee'].split('.')[-1], []))
            own_id = _id(path, sym['symbol'], sym['start_line'])
            own = groups.get(own_id)
            if own and own_id in changed_ids:
                for call in own['calls']:
                    callee = call['callee'].split('.')[-1]
                    matches.extend(add(path, other, other['start_line']) for other in parsed[path]
                                   if other['symbol'].split('.')[-1] == callee and other is not sym)
            if matches:
                own = add(path, sym, sym['start_line'])
                for match in matches:
                    if match['group_id'] == own['group_id']:
                        continue
                    for a, b in [(own, match), (match, own)]:
                        if b['group_id'] not in a['related_group_ids']:
                            a['related_group_ids'].append(b['group_id'])
                        if 'syntactic_neighbor_of_changed_symbol' not in a['reasons']:
                            a['reasons'].append('syntactic_neighbor_of_changed_symbol')

    ledger = []
    identified_alerts = unique_alerts([{**a, 'alert_id': str(a.get('alert_id', f'row-{i}'))}
                                      for i, a in enumerate(alerts)])
    for index, alert in enumerate(identified_alerts):
        # Allowlist fields; never forward accidental labels/evaluator metadata.
        original_id = str(alert.get('scanner_original_alert_id', alert['alert_id']))
        aid = alert['alert_id']
        locs = _locations(alert, source)
        linked = []
        for loc in locs:
            if loc['path'] not in changed:
                continue
            sym = _enclosing(load(loc['path']), loc['line'])
            key = _id(loc['path'], sym['symbol'] if sym else '<module>', sym['start_line'] if sym else 1)
            row = groups.get(key)
            # Keep file-level alerts as lower priority, without evicting changed
            # functions merely because the tool flags an unrelated old helper.
            if row is None:
                row = add(loc['path'], sym, loc['line'])
                row['reasons'].append('scanner_in_changed_file')
            reason = ('scanner_flow_intersects_change' if row['group_id'] in changed_ids
                      else 'scanner_flow_in_changed_file') if loc['kind'] == 'scanner_flow_location' else 'scanner_primary_in_review_group'
            if reason not in row['reasons']:
                row['reasons'].append(reason)
            if aid not in row['alert_ids']:
                row['alert_ids'].append(aid)
            linked.append(row['group_id'])
        ledger.append({'alert_id': aid, 'original_alert_id': original_id, 'original_row': index,
                       'tool': str(alert.get('tool', '')), 'rule_id': str(alert.get('rule_id', '')),
                       'path': _safe_path(alert.get('path'), source), 'line': alert.get('line'),
                       'message': str(alert.get('message', ''))[:1400],
                       'locations': locs, 'linked_group_ids': sorted(set(linked)),
                       'policy': 'retained_until_independently_resolved'})

    for row in groups.values():
        is_changed = row['group_id'] in changed_ids
        boundary = bool(BOUNDARY.search(row['symbol']))
        sink_count = sum(bool(SINK.search(c['callee'])) for c in row['calls'])
        changed_guard_count = sum(g['line'] in row['changed_lines'] for g in row['guards'])
        row['rank_score'] = (100 if is_changed else 0) + (35 if is_changed and row['alert_ids'] else 0) + (20 if boundary else 0) + min(15, sink_count * 5) + min(12, changed_guard_count * 4) + (8 if row['related_group_ids'] else 0)
        row['is_changed'] = is_changed
        diagnostic=bool(re.search(r'(^|/)(reproduce[^/]*|.*verification|verify_[^/]*)\.py$',row['path'])
                        or row['symbol'].split('.')[-1].startswith(('test_','verify_')))
        row['review_role']=('agent_validation_artifact' if is_changed and diagnostic else
                            'primary_agent_modified' if is_changed else 'pre_existing_context')
        row['rank_features'] = {'changed': is_changed, 'scanner_alerts': len(row['alert_ids']),
                                'security_boundary_name_heuristic': boundary,
                                'sink_syntax_count': sink_count, 'changed_guard_count': changed_guard_count}
    priority={'primary_agent_modified':0,'agent_validation_artifact':1,'pre_existing_context':2}
    ordered = sorted(groups.values(), key=lambda r: (priority[r['review_role']],
        r['symbol']=='<module>',-r['rank_score'], r['path'], r['start_line'], r['symbol']))
    selected, budget_left = [], max_context_chars
    for row in ordered[:max_groups]:
        lines = files.get(row['path'], '').splitlines()
        start, end = max(1, row['start_line']), min(len(lines), row['end_line'])
        # Preserve changed-line windows for long functions. Full source remains
        # retrievable by path and line; mark every abbreviated group explicitly.
        candidates = set(range(start, min(end + 1, start + 8)))
        anchors = row['changed_lines'] or row['deletion_anchors'] or [start]
        for anchor in anchors:
            candidates.update(range(max(start, anchor - 3), min(end + 1, anchor + 5)))
        if end - start < 100:
            candidates.update(range(start, end + 1))
        limit = min(6000, max(0, budget_left // max(1, min(max_groups, len(ordered)) - len(selected))))
        fragments, used, included = [], 0, []
        for number in sorted(candidates):
            text = f'{number}: {lines[number - 1]}'
            if used + len(text) + 1 > limit:
                break
            fragments.append(text); included.append(number); used += len(text) + 1
        selected.append({**row, 'source': '\n'.join(fragments),
                         'source_included_lines': included,
                         'source_abbreviated': len(included) != max(0, end - start + 1)})
        budget_left -= used
    selected_ids = {r['group_id'] for r in selected}
    for item in ledger:
        item['in_selected_context'] = bool(selected_ids.intersection(item['linked_group_ids']))
        item['line_in_agent_patch']=any(loc['line'] in changed.get(loc['path'],{}).get('added_lines',[])
                                       for loc in item['locations'])
        item['symbol_modified_by_agent']=bool(changed_ids.intersection(item['linked_group_ids']))
        item['review_role']='agent_modified_context' if item['line_in_agent_patch'] else 'pre_existing_context'
        item['provenance_note']='Relative to the submitted patch only; no historical scanner run proves when this warning originated.'
    compact = lambda r: {k: v for k, v in r.items() if k not in {'calls', 'guards'}}
    return {'schema': 'submitted-change-security-plan-v2-change-first', 'labels_used': False,
            'patch_sha256': hashlib.sha256(patch_text.encode()).hexdigest(),
            'source_scope': 'generated final snapshot; submitted patch against masked baseline',
            'ranking': 'changed symbols first; scanner overlap, boundary-name/sink/guard syntax and one-hop syntactic neighbors; no history or labels',
            'limitations': ['AST/name relations are not semantic data flow.',
                           'Deletion anchors locate adjacent current code; deleted symbol identity is not inferred.',
                           'Source/context caps are reported; omitted groups remain available in the inventory.'],
            'counts': {'changed_files': len(changed), 'changed_symbols': len(changed_ids),
                       'all_review_groups': len(groups), 'selected_groups': len(selected),
                       'changed_groups_selected': len(changed_ids & selected_ids),
                       'scanner_alerts': len(alerts), 'scanner_alerts_linked': sum(bool(x['linked_group_ids']) for x in ledger),
                       'scanner_alerts_in_selected_context': sum(x['in_selected_context'] for x in ledger)},
            'changed_files': changed, 'changed_symbols': [compact(r) for r in ordered if r['is_changed']],
            'selected_groups': selected, 'unselected_groups': [compact(r) for r in ordered if r['group_id'] not in selected_ids],
            'scanner_ledger': ledger, 'source_errors': errors}
