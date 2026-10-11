"""Post-detection reference comparison and evidence audit. No benchmark execution."""
import argparse
from collections import Counter
import json
from pathlib import Path

if __package__:
    from .discover_helpers import normalize, snapshot_ref, literal_creation_before_invocation
    from .structure import sha
    from .swe import Archive, read_jsonl, save, jsonl
else:
    from discover_helpers import normalize, snapshot_ref, literal_creation_before_invocation
    from structure import sha
    from swe import Archive, read_jsonl, save, jsonl


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--discovery', type=Path, required=True)
    ap.add_argument('--batch', type=Path, required=True)
    ap.add_argument('--archive', type=Path, required=True)
    ap.add_argument('--paper-results', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    discovery = read_jsonl(args.discovery / 'discovery.jsonl')
    summary = json.loads((args.discovery / 'summary.json').read_text())
    paper = json.loads(args.paper_results.read_text())
    for name, digest in summary['script_hashes'].items():
        assert sha(Path(__file__).with_name(name).read_bytes()) == digest, name
    reference = {(r['run_id'], r['helper']): r for r in paper['cases']}
    nominations = {(r['run_id'], r['path']): r for r in read_jsonl(args.batch / 'nominations.jsonl') if r['nominated']}
    archive = Archive(args.archive, args.batch, args.out)
    candidates, checked_links = [], []
    event_cache, snap_cache = {}, {}
    for r in discovery:
        key = (r['run_id'], r['path'])
        if not r.get('any_version_static_source_writer') and key not in reference:
            continue
        runid = r['run_id']
        if runid not in event_cache:
            event_cache[runid] = {e['event_id']: e for e in archive.run(runid, 'events.jsonl')}
            snap_cache[runid] = {s['snapshot_id']: s for s in archive.run(runid, 'snapshots.jsonl')}
        events, snapshots = event_cache[runid], snap_cache[runid]
        ref = reference.get(key)
        if ref:
            assert ref['helper_sha256'] == r['final_sha256']
            assert ref['task_redundant'] is True
            deletion = Path(ref['deletion']['evidence'])
            assert sha(deletion.read_bytes()) == ref['deletion']['sha256']
        target_observations = []
        for invocation in r['invocations']:
            event = events[invocation['event_id']]
            before, after = snapshots[event['before_snapshot']], snapshots[event['after_snapshot']]
            for version in r['versions']:
                if version['sha256'] != invocation.get('source_sha256'):
                    continue
                for effect in version['effects']:
                    for p in effect['paths']:
                        p = normalize(p, invocation['cwd'])
                        target_observations.append(dict(event_id=event['event_id'], path=p,
                            before_ref=snapshot_ref(before, p), after_ref=snapshot_ref(after, p),
                            exit_code=event.get('exit_code')))
        for link in r['history_links']:
            event = events[link['event_id']]
            before, after = snapshots[event['before_snapshot']], snapshots[event['after_snapshot']]
            hp, tp = normalize(r['path']), normalize(link['target'])
            assert snapshot_ref(after, hp) == link['helper_sha256']
            assert snapshot_ref(before, tp) == link['before_ref']
            assert snapshot_ref(after, tp) == link['after_ref']
            assert link['before_ref'] != link['after_ref']
            if link['helper_version_status'] == 'exact_literal_written_immediately_before_invocation':
                assert literal_creation_before_invocation(event['command'], hp, link['helper_sha256'])
            else:
                assert snapshot_ref(before, hp) == link['helper_sha256']
            checked_links.append(dict(run_id=runid, helper=r['path'], event_id=link['event_id'],
                helper_version_status=link['helper_version_status'],
                helper_version_equals_endpoint=link['helper_endpoint_same_bytes'],
                target=link['target'], ast_change=link['ast_change'], read_same_target=link['read_same_target'],
                command_sha256=sha(event['command']), before_snapshot=event['before_snapshot'],
                after_snapshot=event['after_snapshot'], verified=True))
        directory = args.out / 'evidence' / runid / sha(r['path'])[:12]
        directory.mkdir(parents=True)
        (directory / 'endpoint.py').write_text(archive.blob(r['final_sha256']))
        save(directory / 'events.json', [events[i['event_id']] for i in r['invocations']])
        c = dict(run_id=runid, path=r['path'], stratum=r['stratum'], task=r['task'],
            sha256=r['final_sha256'], static_writer=r.get('any_version_static_source_writer', False),
            history_supported=r['detected'], reference_positive=ref is not None,
            reference_event_recovered=ref is not None and any(l['event_id'] == nominations[key]['event_id'] for l in r['history_links']),
            task_redundant=ref['task_redundant'] if ref else None,
            currency=ref['currency'] if ref else 'not_previously_characterized',
            evidence_dir=str(directory), captured_versions=len(r['versions']),
            versions=r['versions'], helper_transitions=r['helper_transitions'],
            invocations=r['invocations'], target_observations=target_observations,
            history_links=r['history_links'])
        candidates.append(c)
    found = {(r['run_id'], r['path']) for r in discovery if r['detected']}
    static = {(r['run_id'], r['path']) for r in discovery if r.get('any_version_static_source_writer')}
    reference_keys = set(reference)
    results = dict(discovery=summary,
        comparison=dict(reference_files=len(reference), static_reference_recovered=len(reference_keys & static),
            history_reference_recovered=len(reference_keys & found),
            reference_events_recovered=sum(c['reference_event_recovered'] for c in candidates),
            reference_misses=sorted(reference_keys - found), additional_static=sorted(static - reference_keys),
            additional_history=sorted(found - reference_keys)),
        verified_history_links=len(checked_links),
        helper_version_evidence=dict(Counter(l['helper_version_status'] for l in checked_links)),
        target_ast_change=dict(Counter(l['ast_change'] for l in checked_links)),
        helper_version_equals_endpoint=dict(Counter(str(l['helper_version_equals_endpoint']) for l in checked_links)),
        detected_helper_version_counts=dict(Counter(len(r['versions']) for r in discovery if r['detected'])),
        detected_helper_transitions=dict(Counter(t['status'] for r in discovery if r['detected'] for t in r['helper_transitions'])),
        all_links_have_same_target_read=all(l['read_same_target'] for l in checked_links),
        linked_files_by_currency=dict(Counter(c['currency'] for c in candidates if c['history_supported'])),
        task_redundancy=dict(confirmed=sum(c['task_redundant'] is True for c in candidates),
            rejected=sum(c['task_redundant'] is False for c in candidates),
            unknown=sum(c['task_redundant'] is None for c in candidates)),
        scope='Exploratory within-cohort reference recovery; not held-out precision/recall or safe removal.',
        input_hashes={str(p):sha(p.read_bytes()) for p in [args.discovery/'discovery.jsonl',
            args.discovery/'summary.json', args.paper_results, args.batch/'nominations.jsonl']},
        validator_sha256=sha(Path(__file__).read_bytes()))
    save(args.out / 'validation.json', results)
    jsonl(args.out / 'candidate_cases.jsonl', candidates)
    jsonl(args.out / 'checked_history_links.jsonl', checked_links)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
