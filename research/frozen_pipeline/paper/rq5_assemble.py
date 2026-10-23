"""Assemble the complete corrected cohort with explicit outcome lineage."""
from pathlib import Path
import json
from paper.rq5_factorial import run as base
from security_ground_truth.runtime.common import write_json,sha256,utcnow

original=base.ROOT
oracle=original.with_name('rq5_independent_biology_oracle_audit_v2')
adapter=original.with_name('rq5_independent_biology_alias_audit_v3')
final=original.with_name('rq5_independent_biology_final')
roots=[original,oracle,adapter]
results={root:base.read(root/'RESULTS.json') for root in roots}
assert all(v['status']=='completed' and not v['errors'] for v in results.values())
manifest=base.read(original/'manifest.json');lineage={};rows=[]
for case in manifest['cases']:
    cid=case['id']
    source=(adapter if cid=='haddock_extract_symlink__A' else
            oracle if cid in ('rfdiffusion_checkpoint__A','rfdiffusion_checkpoint__B','dockq_handle_lifecycle__A') else original)
    (final/'cases').mkdir(parents=True,exist_ok=True);(final/'continuations').mkdir(parents=True,exist_ok=True)
    base.prior.copy_tree(source/'cases'/cid,final/'cases'/cid)
    base.prior.copy_tree(source/'continuations'/cid,final/'continuations'/cid)
    selected=[r for r in results[source]['records'] if r['case_id']==cid]
    assert len(selected)==4
    for r in selected:
        item=dict(r);item['outcome_source']=str(source);rows.append(item)
    lineage[cid]={'source':str(source),'source_manifest_sha256':sha256(source/'manifest.json')}
manifest.update(protocol_version='corrected-independent-biology-final',utc=utcnow(),primary_cells=40,
    source_lineage=lineage,oracle_corrections=base.read(oracle/'manifest.json')['correction'],
    adapter_correction=base.read(adapter/'manifest.json')['correction'],
    archival_policy='All 40 original cells, all 12 oracle-correction reruns, and all four adapter replays remain available. Primary cells are selected by a documented evaluator correction, not by model outcome.',
    original_cells_reused=24,oracle_rerun_cells=12,adapter_replay_cells=4)
write_json(final/'manifest.json',manifest)
obj=base.gateway()
write_json(final/'RESULTS.json',{'utc':utcnow(),'records':rows,'errors':[],'status':'completed','ledger':obj.ledger.scope_summary(),
    'manifest_sha256':sha256(final/'manifest.json')})
write_json(final/'AUDIT_LINEAGE.json',{'utc':utcnow(),'roots':{str(r):{'result_sha256':sha256(r/'RESULTS.json'),
    'manifest_sha256':sha256(r/'manifest.json'),'cells':len(results[r]['records'])} for r in roots},'primary_selection':lineage})
print(json.dumps({'output':str(final),'primary_cells':len(rows),'ledger':obj.ledger.scope_summary()},indent=2))
