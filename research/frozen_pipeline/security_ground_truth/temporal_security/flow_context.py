"""Push scanner paths and independently attributed history onto current symbols.

Only current source, scanner output, recorded AST edits and exposed prose enter
this module. An absent scanner path is explicit; AST neighbors are not taint flow.
"""
import ast
import hashlib
import json
from pathlib import Path

from .citations import symbols
from .planner import _safe_path, production

POLICY = 'scanner-path-push-v1'


def _node(root, path, line, role, origin, **extra):
    path = _safe_path(path, root)
    if not path or not production(path):
        return None
    target = (root/path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    source = target.read_text(errors='replace'); lines = source.splitlines()
    if type(line) is not int or not 1 <= line <= len(lines):
        return None
    scopes = [s for s in symbols(source) if s['start_line'] <= line <= s['end_line']]
    scope = min(scopes, key=lambda s:s['end_line']-s['start_line']) if scopes else None
    identity = f'{path}:{line}:{role}:{origin}'
    return {'node_id': hashlib.sha256(identity.encode()).hexdigest()[:16], 'path': path,
            'line': line, 'symbol': scope['symbol'] if scope else '<module>',
            'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'symbol_start': scope['start_line'] if scope else 1,
            'symbol_end': scope['end_line'] if scope else len(lines),
            'role': role, 'origin': origin, 'source': lines[line-1].strip()[:240], **extra}


def _neighbors(root, nodes):
    result = []; seen = set()
    for n in nodes:
        if (n['path'], n['symbol'], n['line']) in seen:
            continue
        seen.add((n['path'], n['symbol'], n['line']))
        source = (root/n['path']).read_text(errors='replace')
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for current in ast.walk(tree):
            if isinstance(current, (ast.If, ast.Assert)) and n['symbol_start'] <= current.lineno <= n['symbol_end']:
                guards = isinstance(current, ast.Assert) and current.lineno < n['line']
                guards = guards or any(getattr(x, 'lineno', 0) <= n['line'] <= getattr(x, 'end_lineno', 0)
                                      for x in getattr(current, 'body', []))
                if guards:
                    node = _node(root, n['path'], current.lineno, 'guard_candidate', 'python_ast_syntax',
                                 relation_to=n['node_id'], proves_sanitization=False)
                    if node: result.append(node)
        leaf = n['symbol'].split('.')[-1]
        for current in ast.walk(tree):
            if not isinstance(current, ast.Call): continue
            callee = current.func.id if isinstance(current.func, ast.Name) else current.func.attr if isinstance(current.func, ast.Attribute) else None
            if callee == leaf:
                node = _node(root, n['path'], current.lineno, 'caller_candidate', 'python_ast_name_match',
                             relation_to=n['node_id'], resolved_call_target=False)
                if node: result.append(node)
    unique = {n['node_id']: n for n in result}
    return list(unique.values())[:6]


def build_flows(source_root, alerts, max_bytes=18000):
    root = Path(source_root).resolve(); bundles = []
    for alert in alerts:
        paths = []; seen = set()
        for ci, code in enumerate(alert.get('flow') or []):
            if not isinstance(code, dict): continue
            for ti, thread in enumerate(code.get('threadFlows', [])):
                locations = thread.get('locations', []); nodes = []
                indices = sorted(set([0, len(locations)-1] + list(range(1, min(5, len(locations)-1)))))
                for index in indices:
                    if not 0 <= index < len(locations): continue
                    loc = locations[index].get('location', {}); physical = loc.get('physicalLocation', {})
                    role = 'source_endpoint' if index == 0 and len(locations)>1 else 'sink_endpoint' if index == len(locations)-1 and len(locations)>1 else 'flow_step'
                    node = _node(root, physical.get('artifactLocation', {}).get('uri'),
                                 physical.get('region', {}).get('startLine'), role, 'scanner_sarif',
                                 scanner_index=index, message=loc.get('message', {}).get('text', '')[:180],
                                 role_basis='position_in_scanner_path_not_independent_semantic_proof')
                    if node: nodes.append(node)
                signature = tuple((n['path'],n['line'],n['role']) for n in nodes)
                if nodes and signature not in seen:
                    paths.append({'code_flow':ci, 'thread_flow':ti, 'nodes':nodes,
                                  'omitted_locations':len(locations)-len(nodes)}); seen.add(signature)
        primary = _node(root, alert.get('path'), alert.get('line'), 'warning_location', 'scanner_primary')
        nodes = [n for p in paths[:2] for n in p['nodes']] or ([primary] if primary else [])
        bundles.append({'alert_id':alert['alert_id'], 'tool':alert['tool'], 'rule_id':alert['rule_id'],
                        'path_status':'native_scanner_path' if paths else 'no_native_flow_recorded',
                        'paths':paths[:2], 'omitted_paths':max(0,len(paths)-2), 'primary':primary,
                        'context_nodes':_neighbors(root,nodes)})
    # Reduce each bundle fairly; never silently convert an abbreviated path into
    # a complete one or drop endpoints to make a stronger semantic claim.
    def size(): return len(json.dumps(bundles).encode())
    for bundle in reversed(bundles):
        if size() <= max_bytes: break
        bundle['context_nodes_omitted'] = len(bundle['context_nodes']); bundle['context_nodes'] = []
    for bundle in reversed(bundles):
        if size() <= max_bytes: break
        for path in bundle['paths']:
            if len(path['nodes'])>2:
                path['omitted_locations'] += len(path['nodes'])-2
                path['nodes'] = [path['nodes'][0],path['nodes'][-1]]
        for node in [bundle['primary'], *(n for p in bundle['paths'] for n in p['nodes'])]:
            if node:
                node.pop('message',None);node.pop('role_basis',None);node['source']=node['source'][:100]
    omitted = []
    while size()>max_bytes and bundles:
        bundle=bundles.pop();omitted.append(bundle['alert_id'])
    return {'policy':POLICY,'warnings':bundles,'omitted_alert_ids':omitted,
            'snapshot':'original_scanner_source; re-check current code after edits',
            'limitations':'Endpoint roles come from scanner path position. AST guards/callers are candidates, not verified sanitizers or resolved data flow.'}


def flow_targets(flow_context):
    return list({(n['path'],n['symbol']):{'path':n['path'],'symbol':None if n['symbol']=='<module>' else n['symbol']}
                 for w in flow_context['warnings'] for n in all_nodes(w)}.values())


def all_nodes(warning):
    nodes=[n for p in warning['paths'] for n in p['nodes']]+warning.get('context_nodes',[])
    if warning.get('primary'): nodes.append(warning['primary'])
    return list({n['node_id']:n for n in nodes}.values())


def annotate(flow_context, history, temporal, rationale, max_bytes=10000):
    """Add separate, bounded associations without crossing treatment boundaries."""
    records = [r for channel in ['agent','git'] for r in history.get('temporal',{}).get(channel,{}).get('records',[])] if temporal else []
    cards = history.get('rationale',{}).get('events',[]) if rationale else []
    annotations = []; omitted = 0
    for warning in flow_context.get('warnings',[]):
        for node in all_nodes(warning):
            entry={'alert_id':warning['alert_id'],'node_id':node['node_id'],'path':node['path'],
                   'symbol':node['symbol'],'role':node['role'],'temporal':[],'rationale':[]}
            for rec in records:
                if rec.get('path')!=node['path']:continue
                hints=[h for h in rec.get('symbol_hints',[]) if h['symbol']==node['symbol'] or
                       h['symbol'].startswith(node['symbol']+'.') or node['symbol'].startswith(h['symbol']+'.')]
                anchored=any(a.get('current_symbol')==node['symbol'] for a in rec.get('current_symbol_anchors',[]))
                if not hints and not anchored:continue
                changes=[]
                for change in rec.get('node_changes',[]):
                    if not any(x and (x.get('scope')==node['symbol'] or node['symbol'].startswith(x.get('scope','')+'.'))
                               for x in [change.get('before'),change.get('after')]):continue
                    current_span=None; after=change.get('after')
                    if after and rec.get('after_sha256')==node['source_sha256']:
                        current_span=(after['line'],after['end_line'])
                    elif after and rec.get('source_fidelity')=='acknowledged_editor_fragment_pair':
                        anchors=[a for a in rec.get('current_symbol_anchors',[]) if a.get('field')=='new_str'
                                 and a.get('current_source_sha256')==node['source_sha256']
                                 and a.get('current_symbol')==node['symbol']]
                        spans={(a['start_line']+after['line']-1,a['start_line']+after['end_line']-1) for a in anchors}
                        if len(spans)==1:current_span=spans.pop()
                    direct=bool(current_span and current_span[0]<=node['line']<=current_span[1])
                    changes.append({**change,'current_node_overlap':direct,'current_span':current_span,
                                    'association':'exact_after_snapshot_or_fragment_lines' if direct else 'symbol_only_historical_location'})
                entry['temporal'].append({'event_id':rec['event_id'],'history_channel':rec.get('history_channel'),
                    'association':'current_fragment_symbol_anchor' if anchored else 'qualified_symbol_history',
                    'changes':changes[:4], 'hints':[h['hint'][:500] for h in hints[:2]],
                    'continuous_transition':rec.get('continuous_transition'),
                    'flow_node_identity_across_versions_proven':False,
                    'interpretation':'Node overlap identifies syntactic change; flow semantics and exploitability still require current verification.'})
            for card in cards:
                links=[l for l in card.get('links',[]) if l['path']==node['path']]
                anchored=any(a.get('current_symbol')==node['symbol'] for l in links for a in l.get('current_symbol_anchors',[]))
                mentioned=node['symbol'] in card.get('mentioned_target_symbols',[])
                if links and (anchored or mentioned):
                    entry['rationale'].append({'event_id':card['event_id'],'span_id':card['span_id'],
                        'association':'current_fragment_symbol_anchor' if anchored else 'explicit_symbol_mention',
                        'assumption_status':'original claim to test; no inferred belief supplied'})
            if entry['temporal'] or entry['rationale']:
                entry['temporal']=entry['temporal'][:2];entry['rationale']=entry['rationale'][:2]
                if len(json.dumps([*annotations,entry]).encode()) <= max_bytes:annotations.append(entry)
                else:omitted+=1
    return {'nodes':annotations,'omitted_node_annotations':omitted,
            'temporal_enabled':temporal,'rationale_enabled':rationale}
