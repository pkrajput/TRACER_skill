"""Check all SWE evidence links and emit inspectable version annotations.

Source-flow labels below record Codex's inspection of these finite cases, not an
independently validated general-purpose data-flow analysis.
"""
import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import zipfile

if __package__:
    from .structure import definitions, payloads, sha, state_at
    from .swe import read_jsonl, save, jsonl
else:
    from structure import definitions, payloads, sha, state_at
    from swe import read_jsonl, save, jsonl


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--swe', type=Path, required=True)
    ap.add_argument('--archive', type=Path, required=True)
    args = ap.parse_args()
    links = read_jsonl(args.swe/'links.jsonl')
    helpers = read_jsonl(args.swe/'helpers.jsonl')
    by_helper = {(h['run_id'],h['path']):h for h in helpers}
    z = zipfile.ZipFile(args.archive)
    events, snapshots = {}, {}
    validation, reviews, annotations, graph_nodes, graph_edges = [], [], [], {}, []
    for h in helpers:
        rid = h['run_id']
        if rid not in events:
            events[rid] = {r['event_id']:r for r in map(json.loads,z.read(f'ghost_model_families/runs/{rid}/events.jsonl').splitlines())}
            snapshots[rid] = {r['snapshot_id']:r for r in map(json.loads,z.read(f'ghost_model_families/runs/{rid}/snapshots.jsonl').splitlines())}
        e = events[rid][h['event_id']]
        snap = snapshots[rid][e['after_snapshot']]
        ref = {**snap['files'],**snap.get('tmp_files',{})}.get(h['path'])
        assert ref==h['sha256'], (rid,h['path'],'helper differs at action')
        source = (Path(h['evidence_dir'])/'helper.py').read_bytes()
        assert sha(source)==ref
        validation.append(dict(run_id=rid,helper=h['path'],helper_matches_action_and_endpoint=True,helper_sha256=ref))
    entity_keys = set()
    for link in links:
        h = by_helper[(link['run_id'],link['helper'])]
        e = events[link['run_id']][link['event_id']]
        source = (Path(h['evidence_dir'])/'helper.py').read_text()
        ps = payloads(source)
        p = next(p for p in ps if p['literal_line']==link['literal_line'])
        u = next(u for u in p['definitions'] if u['ast_sha256']==link['payload_unit']['ast_sha256'] and u['qualified_name']==link['payload_unit']['qualified_name'])
        assert u['ast_sha256']==link['target_unit']['ast_sha256']
        for label in ['before','after','final']:
            file = Path(link['evidence_dir'])/(label+'.py')
            raw = file.read_bytes()
            assert sha(raw)==link['source_refs'][label]
            ds = definitions(raw.decode())
            expected = 'current' if label=='after' else link['before_status'] if label=='before' else link['endpoint_status']
            assert state_at(link['target_unit'],ds)==expected
        if link['origin']!='observed_introduction': continue
        assert e.get('exit_code')==0
        assert 'search_pattern' not in p['roles'], 'Primary output cannot be a search-only match'
        key = (link['run_id'],link['helper'],link['target_path'],link['target_unit']['qualified_name'],link['target_unit']['ast_sha256'])
        assert key not in entity_keys, 'Do not count duplicated literals as independent entities'
        entity_keys.add(key)
        tree = ast.parse(source)
        # Reviewed case families: replacement, regex replacement, list insertion,
        # and list-slice assignment. Preserve source locations for external audit.
        calls = [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
        sinks = [dict(line=n.lineno,expression=ast.unparse(n)) for n in calls if n.func.attr in {'write','writelines','write_text'}]
        if p['roles']==['unresolved']:
            mechanism = 'regex replacement' if any(n.func.attr=='sub' for n in calls) else 'list slice replacement'
        elif 'insert_argument' in p['roles']: mechanism='list insertion'
        else: mechanism='string replacement'
        reads_writes = [dict(line=n.lineno,expression=ast.unparse(n)) for n in ast.walk(tree)
                       if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='open']
        review = dict(link_id=link['id'],reviewer='Codex source inspection; not independent human validation',
            conclusion='Payload participates in target-writing computation; recorded command invokes helper; exact definition newly appears in after snapshot.',
            mechanism=mechanism,literal_names=p['names'],literal_line=p['literal_line'],sinks=sinks,file_operations=reads_writes,
            event_exit_code=e['exit_code'],command_file=str(Path(h['evidence_dir'])/'recorded_command.txt'),
            caveat='Recorded command can include helper creation and invocation in one action; no within-process instrumentation.')
        reviews.append(review)
        statuses=[t['status'] for t in link['transitions']]
        annotation=dict(link_id=link['id'],run_id=link['run_id'],artifact=link['helper'],literal_line=link['literal_line'],
            target=dict(path=link['target_path'],qualified_name=link['target_unit']['qualified_name']),
            kind='embedded source definition',observed_write_event=link['event_id'],status=link['endpoint_status'],
            historical_ast_sha256=link['target_unit']['ast_sha256'],endpoint_ast_sha256=link['final_unit']['ast_sha256'],
            reverted=('superseded' in statuses and link['endpoint_status']=='current'),
            message=('This retained payload matches an observed earlier version. The endpoint definition has a different AST.'
                     if link['endpoint_status']=='superseded' else 'This retained payload matches the endpoint definition AST.'),
            limitations='No correctness, reachability, deletion safety, retrieval ranking, or behavioral equivalence judgment.')
        annotations.append(annotation)
        aid='artifact:'+sha(link['run_id']+':'+link['helper'])[:20]
        pid='payload:'+link['id']
        eid='event:'+link['event_id']
        sid='symbol-version:'+sha(link['run_id']+link['target_path']+link['target_unit']['qualified_name']+link['target_unit']['ast_sha256'])[:20]
        fid='symbol-version:'+sha(link['run_id']+link['target_path']+link['target_unit']['qualified_name']+link['final_unit']['ast_sha256'])[:20]
        graph_nodes[aid]=dict(id=aid,type='retained_artifact',run_id=link['run_id'],path=link['helper'],sha256=h['sha256'])
        graph_nodes[pid]=dict(id=pid,type='embedded_definition',line=p['literal_line'],ast_sha256=u['ast_sha256'])
        graph_nodes[eid]=dict(id=eid,type='recorded_action',event_id=link['event_id'])
        graph_nodes[sid]=dict(id=sid,type='source_definition_version',path=link['target_path'],unit=link['target_unit'])
        graph_nodes[fid]=dict(id=fid,type='source_definition_version',path=link['target_path'],unit=link['final_unit'])
        for a,b,kind in [(aid,pid,'contains'),(pid,eid,'reviewed_payload_use'),(eid,sid,'observed_after_action'),(pid,sid,'exact_AST_match')]:
            graph_edges.append(dict(source=a,target=b,type=kind,link_id=link['id']))
        graph_edges.append(dict(source=pid,target=fid,type='endpoint_'+link['endpoint_status'],link_id=link['id']))
    jsonl(args.swe/'validation.jsonl',validation)
    jsonl(args.swe/'source_flow_review.jsonl',reviews)
    jsonl(args.swe/'context_annotations.jsonl',annotations)
    save(args.swe/'version_graph.json',dict(nodes=list(graph_nodes.values()),edges=graph_edges,
        note='Prototype construction/version relation graph. No CFG or sound whole-program DFG is claimed.'))
    primary=[l for l in links if l['origin']=='observed_introduction']
    summary=dict(helper_hashes_checked=len(validation),links_checked=len(links),primary_unique_entities=len(entity_keys),
        primary_runs=len({l['run_id'] for l in primary}),primary_tasks=len({l['task'] for l in primary}),
        primary_helpers_with_no_executable_definitions=sum(not by_helper[(l['run_id'],l['helper'])]['executable_definitions'] for l in primary),
        by_stratum={s:dict(Counter(l['endpoint_status'] for l in primary if l['stratum']==s)) for s in ['repository','external_tmp']},
        endpoint_reversions=sum(a['reverted'] for a in annotations),
        superseded_code_ast_changes=sum(l['endpoint_status']=='superseded' and not l['code_ast_unchanged'] for l in primary),
        review_mechanisms=dict(Counter(r['mechanism'] for r in reviews)))
    save(args.swe/'validation_summary.json',summary)
    print(json.dumps(summary,indent=2))


if __name__=='__main__': main()
