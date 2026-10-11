"""Join saved SWE oracle checks with structural results; execute no subject code."""
import argparse
from collections import Counter
import json
from pathlib import Path

if __package__:
    from .structure import sha
    from .swe import read_jsonl, save
else:
    from structure import sha
    from swe import read_jsonl, save


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--batch', type=Path, required=True)
    ap.add_argument('--structural', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    evidence = {}

    def read(path):
        raw = path.read_bytes()
        evidence[str(path)] = sha(raw)
        return json.loads(raw)

    def vector(result):
        assert result['valid'] and result['verdict'] == 'pass'
        assert result['checks'] and not result['missing_tests']
        return result['checks']

    def same_oracle(a, b):
        for key in ['oracle_command_hash', 'test_manifest_hash']:
            assert a[key] == b[key], key

    census_file = args.batch/'endpoint_census_final.jsonl'
    evidence[str(census_file)] = sha(census_file.read_bytes())
    census = [r for r in read_jsonl(census_file) if r['benchmark'] == 'swebench']
    eligible = {r['run_id']:r for r in census if r['eligible']}
    helpers = read_jsonl(args.structural/'helpers.jsonl')
    links = read_jsonl(args.structural/'links.jsonl')
    primary = [l for l in links if l['origin'] == 'observed_introduction']
    for name in ['helpers.jsonl', 'links.jsonl', 'validation_summary.json', 'summary.json']:
        p = args.structural/name
        evidence[str(p)] = sha(p.read_bytes())
    baselines = {}
    for rid in eligible:
        a = read(args.batch/'oracle_baselines'/rid/'first/result.json')
        b = read(args.batch/'oracle_baselines'/rid/'repeat/result.json')
        same_oracle(a,b)
        assert vector(a) == vector(b), rid
        baselines[rid] = a

    deletions = {}
    for path in sorted((args.batch/'individual_deletions').glob('*/*/result.json')):
        r = read(path)
        assert r['run_id'] in eligible and len(r['removed']) == 1
        b = baselines[r['run_id']]
        same_oracle(b,r)
        assert vector(r) == vector(b)
        assert r['oracle_redundant']
        key = (r['run_id'], r['removed'][0])
        assert key not in deletions
        deletions[key] = dict(evidence=str(path),sha256=evidence[str(path)],
            outcome_vector_sha256=sha(json.dumps(r['checks'],sort_keys=True)),
            oracle_command_hash=r['oracle_command_hash'],test_manifest_hash=r['test_manifest_hash'])
    expected = {(h['run_id'],h['path']) for h in helpers}
    assert set(deletions) == expected

    joint = []
    for rid in sorted({h['run_id'] for h in helpers}):
        folder = args.batch/'cleanup'/rid
        reviewed = read(folder/'evidence.json')
        paths = {p for run,p in expected if run == rid}
        assert set(reviewed['accepted']) == paths and reviewed['joint_preservation']
        repeats=[]
        for i in range(2):
            path = folder/f'combined-{i}/result.json'
            r = read(path)
            same_oracle(baselines[rid],r)
            assert set(r['removed']) == paths
            assert vector(r) == vector(baselines[rid])
            repeats.append(str(path))
        joint.append(dict(run_id=rid,helpers=len(paths),repeated_vector_equality=True,evidence=repeats))

    cases = []
    for h in helpers:
        ls = [l for l in primary if l['run_id']==h['run_id'] and l['helper']==h['path']]
        assert len(ls) <= 1, 'Revisit helper-level counting when multiple primary definitions occur'
        status = ls[0]['endpoint_status'] if ls else 'unlinked'
        cases.append(dict(run_id=h['run_id'],task=h['task'],helper=h['path'],stratum=h['stratum'],
            helper_sha256=h['sha256'],construction_role='previously nominated source-writing helper',
            construction_link_inspected=bool(ls),task_redundant=True,currency=status,
            structural_link_ids=[l['id'] for l in ls],deletion=deletions[(h['run_id'],h['path'])]))
    models=[]
    for model in sorted({r['model'] for r in census}):
        rs=[r for r in census if r['model']==model]
        ids={r['run_id'] for r in rs}
        models.append(dict(model=model,recorded=len(rs),eligible=sum(r['eligible'] for r in rs),
            helpers=sum(h['run_id'] in ids for h in helpers),
            linked=sum(l['run_id'] in ids for l in primary),
            superseded=sum(l['run_id'] in ids and l['endpoint_status']=='superseded' for l in primary)))
    summary = dict(recorded_runs=len(census),eligible_runs=len(eligible),
        exclusions=dict(Counter(r['exclusion_reason'] for r in census if not r['eligible'])),
        helpers=len(helpers),helper_runs=len(joint),individual_vector_equalities=len(deletions),
        baseline_vector_equalities=len(baselines),combined_vector_equalities=2*len(joint),
        linked_helpers=len(primary),linked_runs=len({l['run_id'] for l in primary}),
        linked_tasks=len({l['task'] for l in primary}),
        currency=dict(Counter(c['currency'] for c in cases)),
        redundancy_by_currency={s:dict(helpers=sum(c['currency']==s for c in cases),
            task_redundant=sum(c['currency']==s and c['task_redundant'] for c in cases))
            for s in ['current','superseded','unlinked']},
        locations={s:dict(Counter(c['currency'] for c in cases if c['stratum']==s)) for s in ['repository','external_tmp']})
    args.out.parent.mkdir(parents=True,exist_ok=True)
    save(args.out,dict(scope='SWE-bench / mini-SWE-agent only',summary=summary,cases=cases,
        model_coverage=models,joint_checks=joint,evidence_sha256=evidence,
        method='Read and compare saved outcome vectors and oracle identifiers. No new oracle or subject-code execution.',
        limits='Structural linking starts from frozen nominations. Source-flow review is assistant inspection, not independent human validation. Task redundancy is oracle-relative.',
        script_sha256=sha(Path(__file__).read_bytes())))
    print(json.dumps(summary,indent=2))


if __name__=='__main__': main()
