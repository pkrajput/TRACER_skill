"""Offline retrospective audit ONLY. Never imported by the investigator/runtime.

Reads evaluator-only labels, fixes and logs to diagnose frozen v6 outputs. No
network, model gateway, container, scanner or benchmark execution is invoked.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import statistics

from .citations import matching_quote, source_hash, symbols
from .score import cluster_bootstrap, summarize
from security_ground_truth.runtime.test_results import parse_test_log

ARMS = ('C0','C1','C2','C3')


def read(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def patch_ranges(text, old=True):
    """Parse git and difflib patches without mixing adjacent files/hunks."""
    result=defaultdict(set);path=None;line=None;active=False;deleted=False
    for row in text.splitlines():
        if row.startswith('--- '):
            path=row[4:].split('\t')[0];path=path[2:] if path.startswith('a/') else path
            active=False
        elif row.startswith('+++ '):
            if not old:
                path=row[4:].split('\t')[0];path=path[2:] if path.startswith('b/') else path
            active=False
        elif row.startswith('@@ '):
            m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)',row)
            line=int(m.group(1 if old else 2)) if m else None;active=bool(m);deleted=False
        elif active and path and line is not None:
            if row.startswith('-'):
                result[path].add(max(1,line))
                if old:line+=1
                deleted=True
            elif row.startswith('+'):
                if not old or not deleted:result[path].add(max(1,line))
                if not old:line+=1
            elif row.startswith(' '):line+=1;deleted=False
    return {p:sorted(v) for p,v in result.items() if p!='/dev/null'}


def reference_symbols(text):
    result=defaultdict(set);path=None
    for row in text.splitlines():
        if row.startswith('+++ '):
            path=row[4:].split('\t')[0];path=path[2:] if path.startswith('b/') else path
        if path and (row.startswith('@@ ') or row.startswith(('+','-',' '))):
            m=re.search(r'\b(?:async\s+)?def (\w+)\s*\(',row)
            if m:result[path].add(m.group(1))
    return {k:sorted(v) for k,v in result.items()}


def phase_artifacts(base):
    phases={}
    for phase in ['func','sec']:
        p=base/phase/'artifacts';result=read(p/'result.json',{})
        stdout=(p/'test.stdout').read_text(errors='replace') if (p/'test.stdout').exists() else ''
        stderr=(p/'test.stderr').read_text(errors='replace') if (p/'test.stderr').exists() else ''
        terminal=parse_test_log(stdout,stderr,result.get('exit_code'),result.get('status'))
        phases[phase]={'status':result.get('status'), 'exit_code':result.get('exit_code'),
            'terminal_recognized':terminal.get('recognized',False),
            'failure_nodes':terminal.get('failure_nodes',[]),'error_nodes':terminal.get('error_nodes',[]),
            'artifact_directory':str(p)}
    return phases


def quote_category(source, action):
    quote=action.get('evidence_quote','')
    if not quote.strip():return 'missing_quote'
    if matching_quote(source,quote):return 'whitespace_or_display_prefix_only'
    if '...' in quote or '…' in quote:return 'abbreviated_or_ellipsis_quote'
    return 'text_not_in_current_buffer'


def audit_trajectory(cell, case):
    """Replay only successful TEXT edits, never archived code or shell actions."""
    trajectory=read(cell/'trajectory.json',[]); buffers={}; reads=defaultdict(list); truncations=defaultdict(list)
    hypotheses={}; errors=Counter(); roots=Counter(); examples=[]; requests=[]
    for turn in trajectory:
        requests.append(turn['request_id'])
        for a,o in zip(turn['answer'].get('actions',[]),turn['observations']):
            h=hypotheses.get(a.get('hypothesis_id'),{})
            path=a.get('path') or h.get('path')
            if path and path not in buffers:
                target=(Path(case['baseline'])/'source'/path).resolve()
                root=(Path(case['baseline'])/'source').resolve()
                if target.is_relative_to(root) and target.is_file():
                    buffers[path]=target.read_text(errors='replace')
            source=buffers.get(path,'')
            if o.get('status')=='invalid_action':
                error=o['error'];errors[error]+=1;kind=None
                if error.startswith('Cite lines from a read of the CURRENT file'):
                    start=a.get('evidence_start_line');end=a.get('evidence_end_line',start)
                    if type(start) is not int or type(end) is not int or not 1<=start<=end:
                        kind='invalid_or_missing_line_range'
                    elif end-start>=160:kind='range_exceeds_160_lines'
                    elif end>len(source.splitlines()):kind='line_range_beyond_current_file'
                    elif any(x[0]==source_hash(source) and x[1]<=start<=end<=x[3] and end>x[2]
                             for x in truncations[path]):kind='display_truncation_omitted_requested_lines'
                    elif not reads[path]:kind='no_prior_explicit_read_initial_context_not_registered'
                    elif any(x[1]<=start<=end<=x[2] and x[0]!=source_hash(source) for x in reads[path]):
                        kind='stale_read_after_source_edit'
                    elif any(x[0]==source_hash(source) for x in reads[path]):
                        kind='range_outside_current_read_including_truncation'
                    else:kind='stale_read_and_different_range'
                elif error.startswith('A conclusive static assessment needs an exact quote'):
                    kind=quote_category(source,a)
                if kind:
                    roots[kind]+=1
                    if len(examples)<8:examples.append({'step':turn['step'],'action':a,'root_cause':kind})
            elif a.get('action')=='read':
                start=max(1,int(a.get('start',1)));end=start+len(o.get('source','').splitlines())-1
                if len(o.get('source',''))==18000:
                    end-=1
                    truncations[path].append((source_hash(source),start,end,
                        min(len(source.splitlines()),start+min(160,max(1,int(a.get('lines',120))))-1)))
                reads[path].append((source_hash(source),start,end))
            elif a.get('action')=='edit' and o.get('status')=='edited':
                if source.count(a['old'])!=1:raise ValueError('Offline edit replay differs: '+str(cell))
                buffers[path]=source.replace(a['old'],a['new'],1)
            elif a.get('action')=='hypothesis' and o.get('hypothesis_id'):
                hypotheses[o['hypothesis_id']]=o
    result=read(cell/'result.json',{})
    return {'rejected':sum(errors.values()),'errors':dict(errors),'citation_roots':dict(roots),
            'examples':examples,'request_ids':requests,'status':result.get('status'),
            'model_calls':result.get('model_calls',0),'finish_requirements':result.get('finish_requirements_at_end',[]),
            'unvalidated_patch_rejected':result.get('unvalidated_patch_retained_separately',False)}


def probe_category(feedback):
    text=feedback.get('traceback','')
    if 'Record a named, scalar behavioral observation' in text:return 'observation_serializer_rejected_non_scalar'
    if 'Observation limit exceeded' in text:return 'observation_count_limit'
    if 'settings are not configured' in text or 'settings.configure()' in text:return 'django_missing_settings'
    if 'AppRegistryNotReady' in text:return 'django_registry_not_ready'
    if 'ModuleNotFoundError' in text or 'ImportError' in text:return 'missing_import_or_dependency'
    if 'SyntaxError' in text or 'IndentationError' in text:return 'generated_python_syntax'
    if 'AttributeError' in text:return 'attribute_or_fixture_error'
    if 'TypeError' in text:return 'call_signature_or_type_error'
    if 'NameError' in text:return 'undefined_name_in_check'
    if 'AssertionError' in text:return 'assertion_in_check_or_target'
    return 'other_target_or_check_exception'


def failed_edit(case,row,cell,audit):
    task=read(Path(case['case_path'])/'task.json');patch=(cell/'candidate.patch').read_text()
    ranges=patch_ranges(patch);reference=reference_symbols(task['security_patch'])
    ref_files=set(patch_ranges(task['security_patch']))
    changed=[]
    for path,lines in ranges.items():
        f=Path(case['baseline'])/'source'/path
        if not f.exists():continue
        ss=symbols(f.read_text(errors='replace'))
        for line in lines:
            candidates=[s for s in ss if s['start_line']<=line<=s['end_line']]
            symbol=min(candidates,key=lambda s:s['end_line']-s['start_line'])['symbol'] if candidates else '<module>'
            if (path,symbol) not in changed:changed.append((path,symbol))
    overlap=sorted(set(ranges)&ref_files)
    matching=[(p,s) for p,s in changed if s.split('.')[-1] in reference.get(p,[])]
    phases=phase_artifacts(cell/'evaluation')
    baseline_phases=phase_artifacts(Path(case['case_path'])/'runs/agent')
    test_names=sorted(set(re.findall(r'^\+\s*(?:async\s+)?def (test\w*)\(',task['test_patch'],re.M)))
    failed_nodes=phases['sec']['failure_nodes']+phases['sec']['error_nodes']
    matched_tests=[n for n in failed_nodes if any(t in str(n) for t in test_names)]
    input_alerts={a['alert_id']:a for a in read(cell/'input.json',{}).get('scanner_alerts',[])}
    hypotheses=read(cell/'hypotheses.json',{})
    reviewed=[{k:h.get(k) for k in ['hypothesis_id','path','line','mechanism','preconditions','security_property','history_use','alert_ids']}
              for h in hypotheses.values() if h.get('path') in ranges]
    for h in reviewed:
        h['linked_scanner_rules']=[input_alerts[i]['rule_id'] for i in h.get('alert_ids') or [] if i in input_alerts]
    if not all(p['terminal_recognized'] for p in baseline_phases.values()):
        category='baseline_execution_not_verified'
    elif not all(p['terminal_recognized'] for p in phases.values()):category='after_execution_not_verified'
    elif not overlap:category='no_direct_reference_file_overlap'
    elif matching and matched_tests:category='reference_symbol_edited_target_test_still_fails'
    elif matching:category='reference_symbol_edited_failure_needs_semantic_review'
    elif reference:category='same_reference_file_different_or_unresolved_symbol'
    else:category='same_reference_file_symbol_mapping_unavailable'
    return {'case_key':case['case_key'],'instance_id':case['instance_id'],'generator':case['model_name'],
            'category':category,'changed_symbols':changed,'reference_files':sorted(ref_files),
            'reference_symbol_names':reference,'direct_file_overlap':overlap,'named_symbol_overlap':matching,
            'reference_cwe_ids':task.get('cwe_ids',[]),'investigated_mechanisms_on_edited_files':reviewed,
            'security_test_failures':matched_tests,'all_failure_nodes':failed_nodes,
            'repair_status':audit['status'],'turn_limit':audit['status']=='turn_limit',
            'unfinished_requirements':audit['finish_requirements'],'rejected_actions':audit['rejected'],
            'baseline_execution':baseline_phases,'after_execution':phases,
            'evidence_paths':{'patch':str(cell/'candidate.patch'),'transcript':str(cell/'trajectory.json'),
                              'reference_fix':str(Path(case['case_path'])/'security_fix.patch')},
            'interpretation':'Reference-file/name overlap is a localization proxy, not proof that a different repair cannot work. A retained patch can be partial at turn limit.'}


def build(root,out):
    run=root/'experiment';cases=read(run/'ready.json');bykey={c['case_key']:c for c in cases}
    original=read(root/'diagnostic_audit/report/RESULTS.json');rows=original['rows']
    diag=read(root/'diagnostic_audit/report/DIAGNOSTIC_REPORT.json')
    pre=read(root/'diagnostic_audit/preflight/results.json')
    seeded={x['case_key'] for x in pre if x['initial_scanner_alerts']}
    dev_tasks=set(diag['known_development_exposure']['development_task_ids'])
    errors=Counter();citation_roots=Counter();probes=Counter();cells={};failed=[]
    for row in rows:
        key,arm=row['case_key'],row['arm'];cell=run/'cells'/key/arm
        audit=audit_trajectory(cell,bykey[key]);cells[(key,arm)]=audit
        errors.update(audit['errors']);citation_roots.update(audit['citation_roots'])
        for p in (cell/'checks').glob('*/feedback.json'):
            f=read(p)
            if f.get('status')=='check_exception':probes[probe_category(f)]+=1
        if arm=='C3' and row['patch_changed'] and not row['before']['sec_pass'] and not row['baseline_infrastructure_incomplete'] and not row['after']['sec_pass']:
            failed.append(failed_edit(bykey[key],row,cell,audit))
    strata={}
    for label,keys in [('SAST-seeded',seeded),('Unseeded',set(bykey)-seeded)]:
        selected=[r for r in rows if r['case_key'] in keys]
        strata[label]={}
        for arm in ARMS:
            rs=[r for r in selected if r['arm']==arm];summary=summarize(rs,len(keys))
            audits=[cells[(r['case_key'],arm)] for r in rs]
            summary.update(average_rejected_actions=statistics.mean(a['rejected'] for a in audits),
                           rejected_actions=sum(a['rejected'] for a in audits),
                           turn_limit_count=sum(a['status']=='turn_limit' for a in audits),
                           turn_limit_rate=sum(a['status']=='turn_limit' for a in audits)/len(rs))
            strata[label][arm]=summary
        strata[label]['paired_contrasts']={arm:cluster_bootstrap(selected,treatment_arm=arm) for arm in ARMS[1:]}
    # Audit terminal execution separately; never rewrite frozen v6 outcomes.
    execution=[]
    for case in cases:
        b=phase_artifacts(Path(case['case_path'])/'runs/agent')
        execution.append({'case_key':case['case_key'],'baseline':b,
                          'baseline_verified':all(p['terminal_recognized'] for p in b.values()),
                          'frozen_baseline_score':case['official_baseline_score']})
    verified_keys={x['case_key'] for x in execution if x['baseline_verified']}
    eligible={c['case_key'] for c in cases if c['instance_id'] in dev_tasks and c['case_key'] in verified_keys}
    # Publish a separate four-way matched sensitivity analysis, leaving all
    # frozen count-mode rows unchanged. Unknown execution is never a safe label.
    valid_after={}
    for row in rows:
        key,arm=row['case_key'],row['arm']
        if not row['patch_changed']:
            valid_after[(key,arm)]=key in verified_keys
        else:
            phases=phase_artifacts(run/'cells'/key/arm/'evaluation')
            valid_after[(key,arm)]=all(p['terminal_recognized'] for p in phases.values())
    all_valid={k for k in verified_keys if all(valid_after.get((k,a),False) for a in ARMS)}
    strict={}
    for label,keys in [('SAST-seeded',seeded&all_valid),('Unseeded',(set(bykey)-seeded)&all_valid)]:
        strict[label]={a:summarize([r for r in rows if r['case_key'] in keys and r['arm']==a],len(keys)) for a in ARMS}
    regressions=[r for r in rows if r['arm']=='C3' and r['before']['sec_pass'] and not r['after']['sec_pass']]
    # Deterministic calibration: exposed regressions, failed edits, then friction,
    # stratified warning presence; never select on new method outcomes.
    reasons=defaultdict(list);selected=[]
    def add(key,reason):
        if key not in eligible:return
        if key not in selected and len(selected)<20:selected.append(key)
        if key in selected:reasons[key].append(reason)
    for row in regressions:add(row['case_key'],'eligible_frozen_C3_regression')
    for label,want_seed in [('seeded_failed_edit',True),('unseeded_failed_edit',False)]:
        candidates=[f for f in failed if f['case_key'] in eligible and (f['case_key'] in seeded)==want_seed]
        candidates.sort(key=lambda f:(-f['rejected_actions'],f['case_key']))
        used_tasks=set()
        for f in candidates:
            if f['instance_id'] in used_tasks:continue
            add(f['case_key'],label);used_tasks.add(f['instance_id'])
            if len(used_tasks)>=6:break
    ordered=sorted(eligible,key=lambda k:(-sum(cells[(k,a)]['rejected'] for a in ['C0','C3']),k))
    for key in ordered:
        if len(selected)>=20:break
        add(key,'high_rejection_exposed_control')
    assert len(selected)==20 and set(selected)<=eligible
    protected={c['case_key'] for c in cases if c['instance_id'] not in dev_tasks}
    assert not (set(selected)&protected)
    ledger=Path('/raid/prateek/ghost_code/security_experiments/20261014/investigator/budget.sqlite')
    connection=sqlite3.connect('file:'+str(ledger)+'?mode=ro',uri=True)
    costs={};cell_costs=defaultdict(int)
    for ident,micro,raw in connection.execute('select id,micro_usd,details from requests'):
        costs[ident]=micro
        detail=json.loads(raw)
        if detail.get('cell_id','').startswith('temporal_security_v2_rationale:'):
            cell_costs[detail['cell_id']]+=micro
    accounted=sum(costs.values())/1e6
    selected_costs=[cell_costs['temporal_security_v2_rationale:'+k+':'+a]/1e6 for k in selected for a in ['C0','C3']]
    known=sum('temporal_security_v2_rationale:'+k+':'+a in cell_costs for k in selected for a in ['C0','C3'])
    plan={'status':'LOCAL_PREPARATION_ONLY_PAID_EXECUTION_NOT_AUTHORIZED','model_calls_authorized':0,
          'arms':['C0','C3'],'cases':20,'cells':40,'max_turns_per_cell':22,
          'protected_attempts':len(protected),'protected_task_count':len({bykey[k]['instance_id'] for k in protected}),
          'case_keys':selected,'selection_reasons':dict(reasons),'exposure_rule':'instance_id in frozen prior-development task stratum AND original functional/security terminal execution verified',
          'eligible_completed_development_cases':len(eligible),
          'protected_regressions_audit_only':[r['case_key'] for r in regressions if r['case_key'] in protected],
          'historical_same_cells_accounted_usd':sum(selected_costs),'historical_cost_cells_matched':known,
          'estimated_with_50_percent_margin_usd':sum(selected_costs)*1.5,
          'proposed_incremental_hard_cap_usd':20,'shared_total_cap_usd':699,
          'current_accounted_usd':accounted,'remaining_usd':699-accounted,
          'qualification':'offline tests and development-only evidence preparation; no new candidate generation or benchmark execution',
          'runtime_allowlist_fields':['case_keys','arms','max_turns_per_cell'],
          'hidden_diagnostics_must_not_enter_runtime':True}
    report={'schema':'v6-postmortem-offline-v1','frozen_manifest_sha256':hashlib.sha256((run/'manifest.json').read_bytes()).hexdigest(),
            'source_root':str(root),'strata':strata,'rejected_action_errors':dict(errors),
            'citation_root_causes':dict(citation_roots),'probe_exception_categories':dict(probes),
            'failed_C3_edits':failed,'failed_C3_edit_categories':dict(Counter(f['category'] for f in failed)),
            'failed_C3_edits_at_turn_limit':sum(f['turn_limit'] for f in failed),
            'execution_integrity':execution,'execution_verified_four_arm_strata':strict,
            'calibration':plan,'regression_keys':[r['case_key'] for r in regressions],
            'cells':[{**a,'case_key':k,'arm':arm} for (k,arm),a in cells.items()],
            'zero_spend_snapshot':{'request_count':len(costs),'accounted_micro_usd':sum(costs.values())}}
    write(out/'V6_POSTMORTEM.json',report);write(out/'DEV_CALIBRATION.json',plan)
    # Deliberately separate this minimal selector from evaluator-only annotations.
    write(out/'DEV_CASE_KEYS.json',{'case_keys':selected,'arms':['C0','C3'],'paid_execution_authorized':False})
    return report


def markdown(d,out):
    lines=['# v6 post-mortem and local engineering qualification','',
           '**No paid calls or new cohort runs are authorized.** This is retrospective analysis of immutable v6 artifacts. '
           'Reference fixes and test details in this report are evaluator-only; runtime modules never import this audit.', '',
           '## SAST-seeded versus unseeded', '',
           'The table reproduces the frozen official count-parser scores. The execution-integrity section below identifies '
           'cases where that parser accepted incomplete execution. “Verified conversion” here means the old v6 classification; '
           'it must be read with the stricter completion audit, not as a newly certified label.', '',
           '| Stratum | Arm | FuncPass | SecPass | v6 insecure → secure | v6 secure → nonpass | Edited | Mean rejected actions | Turn limit |',
           '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for name,arms in d['strata'].items():
        for arm in ARMS:
            r=arms[arm];n=r['scored_cells']
            lines.append(f"| {name} | {arm} | {r['func_after_on_scored']}/{n} | {r['sec_after_on_scored']}/{n} | "
                         f"{r['insecure_converted_to_secpass']}/{r['insecure_before_on_scored']} | {r['security_regressions']}/{r['secure_before_on_scored']} | "
                         f"{r['changed_patches']}/{n} ({100*r['changed_patches']/n:.1f}%) | {r['average_rejected_actions']:.2f} | "
                         f"{r['turn_limit_count']}/{n} ({100*r['turn_limit_rate']:.1f}%) |")
    lines+=['','These are paired descriptive results, not proof that history itself causes harm. The unseeded aggregate is worse '
            'for C1/C2/C3 than C0, but baseline execution errors and the small number of discordant outcomes prevent that causal conclusion. '
            'Task-cluster intervals and all pairs are in the JSON. Do not drop unseeded cases to improve the headline result.','',
            '## Execution-integrity correction','']
    bad=[x for x in d['execution_integrity'] if not x['baseline_verified']]
    badsecure=sum(x['frozen_baseline_score']['sec_pass'] for x in bad)
    lines += [f"**{len(bad)}/391 archived baselines lack a recognized terminal result in at least one phase; {badsecure} were nevertheless counted as SecPass.** "
              'The authors’ count-mode failure threshold was applied without checking whether tests finished. '
              'This is a harness integration error, not evidence that the dataset’s intended labels are unreliable. '
              'Keep the original numbers for provenance; use separately reported execution-verified comparisons before drawing scientific conclusions.', '',
              'The public functional gate now requires a recognized terminal summary before applying the original expected-failure allowance. '
              'It parses full logs, not their truncated model-facing tails. No frozen outcome was overwritten. '
              'The final audit also recognizes a completed test process wrapped by GNU make only when both the terminal summary '
              'and the exact recipe Error 1 evidence are present. A generic exit 2 remains unresolved. '
              'This final table supersedes the preliminary 286-case completion audit.', '',
              '### Separate execution-verified, four-arm matched sensitivity table','',
              'All baseline and final phases must have recognized terminal execution. The original benchmark failure allowances still apply. '
              'This excludes incomplete execution rather than silently treating it as a vulnerability label.', '',
              '| Stratum | Arm | Matched cases | FuncPass | SecPass before → after | Insecure → secure | Secure → nonpass |',
              '|---|---|---:|---:|---:|---:|---:|']
    for label,arms in d['execution_verified_four_arm_strata'].items():
        for arm,r in arms.items():
            lines.append(f"| {label} | {arm} | {r['scored_cells']} | {r['func_after_on_scored']} | "
                         f"{r['sec_before_on_scored']} → {r['sec_after_on_scored']} | {r['insecure_converted_to_secpass']}/{r['insecure_before_on_scored']} | "
                         f"{r['security_regressions']}/{r['secure_before_on_scored']} |")
    lines += ['', '## The 153 C3 changed insecure-to-nonpass candidates','',
              f"The frozen classification yields **{len(d['failed_C3_edits'])}** candidates; **{d['failed_C3_edits_at_turn_limit']}** ended at the turn cap. "
              'Turn-limit status overlaps localization categories and does not by itself prove why a repair failed. '
              'The table separates unresolved execution from observed security-test failures.', '',
              '| Offline category | Cases |','|---|---:|']
    for k,v in d['failed_C3_edit_categories'].items():lines.append(f'| {k} | {v} |')
    lines += ['', 'A shared file/function is not a vulnerability-class match. These are reproducible localization categories, '
              'not fabricated semantic judgments. When the exact introduced security test still fails after editing its reference symbol, '
              'the repair did not satisfy that tested property. Other same-file cases remain marked for semantic review. '
              'A patch to another file could be an alternative repair; no direct overlap alone cannot prove irrelevance.', '']
    review=out/'REGRESSION_REVIEW.md'
    if review.exists():lines += [review.read_text(),'']
    lines += ['## Rejected-action root causes','', '| Exact error | Count |','|---|---:|']
    for k,v in sorted(d['rejected_action_errors'].items(),key=lambda kv:-kv[1]):
        lines.append('| '+k.replace('|','\\|').replace('\n',' ')+' | '+str(v)+' |')
    lines+=['','### Citation-specific replay','', '| Replayed cause | Count |','|---|---:|']
    for k,v in d['citation_root_causes'].items():lines.append(f'| {k} | {v} |')
    lines+=['','The 2,589 line-range failures were produced by read/version/range validation, not by whitespace matching. '
            'The separate quote errors are classified independently. Retrospective replay applies successful text edits in memory '
            'and reproduces the read hashes/ranges; it never executes archived commands.', '',
            '## Probe exceptions','', '| Category | Count |','|---|---:|']
    for k,v in sorted(d['probe_exception_categories'].items(),key=lambda kv:-kv[1]):lines.append(f'| {k} | {v} |')
    lines+=['','Serialization and missing Django initialization are actionable harness issues. Missing project dependencies, '
            'incorrect mocks and exceptions from the actual target are separate; the changes do not claim to fix all 1,185 checks.', '',
            '## Calibration plan — explicit approval still required','',
            'Twenty cases are selected only from prior development-exposed task IDs, additionally requiring completed original functional/security execution. The one eligible regression is included. '
            'The two protected regressions remain retrospective audit only, as explicitly confirmed by the user. '
            'The 142 protected attempts / 48 tasks are excluded from preparation and calibration.', '',
            '| Case | Generator | Selection reason |','|---|---|---|']
    for k in d['calibration']['case_keys']:
        c=next((x for x in d['failed_C3_edits'] if x['case_key']==k),{})
        lines.append(f"| `{k}` | {c.get('generator','exposed control')} | {', '.join(d['calibration']['selection_reasons'][k])} |")
    p=d['calibration'];lines += ['',f"Historical accounted cost for these same 40 C0/C3 cells: **${p['historical_same_cells_accounted_usd']:.2f}** "
                  f"({p['historical_cost_cells_matched']}/40 cells matched to the ledger). A 50% allowance gives **${p['estimated_with_50_percent_margin_usd']:.2f}**; "
                  f"proposed incremental hard cap **$20**, within the existing $699 study ceiling. Current accounted total **${p['current_accounted_usd']:.2f}**, "
                  f"remaining **${p['remaining_usd']:.2f}**. The estimate is not an authorization or a provider quote.", '',
              'Local release criteria: citation recovery in one further scripted turn; no accepted stale or changed-literal quotes; '
              'bounded non-scalar recording; explicit Django environment assumptions; rejected incomplete functional execution; '
              'same scanner flows in every arm; temporal/rationale isolation; only development IDs in preparation. '
              'A paid pilot would check tool rejection rate, completed investigations, verified target-reaching checks, functional preservation '
              'and final official security outcomes. SecPass improvement must not be a release gate used to cherry-pick variants.', '',
              '## Per-candidate diagnosis index','',
              '| Case | Category | Edited symbols | Turn limit | Target test still failing |','|---|---|---|---|---|']
    for f in d['failed_C3_edits']:
        syms='; '.join(p+':'+s for p,s in f['changed_symbols'])
        lines.append(f"| `{f['case_key']}` | {f['category']} | {syms.replace('|','/')} | {f['turn_limit']} | {len(f['security_test_failures'])} |")
    lines += ['', 'Full per-case reference mapping, exact failed test identifiers, unfinished obligations, evidence paths, '
              'per-cell error examples and execution metadata are in `postmortem/V6_POSTMORTEM.json`. '
              'These evaluator-only diagnostics must never be copied into model inputs.']
    engineering=out/'ENGINEERING_REVIEW.md'
    if engineering.exists():lines += ['',engineering.read_text()]
    validation=read(out/'LOCAL_VALIDATION.json')
    if validation:
        q=validation['input_qualification'];t=validation['unit_tests']
        lines += ['', '## Recorded local qualification', '',
                  f"- {t['tests']} tests passed; {t['failures']} failures and {t['errors']} errors. Model clients were fake/mocked only.",
                  f"- {q['passed']}/{q['cases']} selected development cases passed input preparation and arm-isolation checks. "
                  f"The bundles contain {q['pushed_warnings']} warnings, {q['native_paths']} native scanner paths and "
                  f"{q['flow_history_associations']} C3 node associations. Largest initial arm bundle: {q['largest_initial_bytes']:,} bytes.",
                  f"- All {validation['frozen_files_checked']} manifest-listed frozen files retain their original hashes.",
                  f"- {validation['new_paid_requests']} new paid requests; ${validation['new_accounted_usd']:.2f} additional accounted spend.",
                  '- The selector hash, code hashes and budget snapshots are recorded in `postmortem/LOCAL_VALIDATION.json`. '
                  'This establishes local harness qualification, not improved model repair performance. Paid execution remains unauthorized.']
    return '\n'.join(lines)+'\n'


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    p.add_argument('--output',type=Path,default=Path(__file__).with_name('postmortem'))
    args=p.parse_args();d=build(args.root,args.output)
    args.output.parent.joinpath('V6_POSTMORTEM.md').write_text(markdown(d,args.output))
    print(json.dumps({'failed_edits':len(d['failed_C3_edits']),'errors':sum(d['rejected_action_errors'].values()),
                      'citation_roots':d['citation_root_causes'],'probe_exceptions':d['probe_exception_categories'],
                      'failed_categories':d['failed_C3_edit_categories'],'budget':d['calibration']['estimated_with_50_percent_margin_usd']}))


if __name__=='__main__':main()
