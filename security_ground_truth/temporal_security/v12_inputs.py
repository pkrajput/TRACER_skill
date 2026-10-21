"""Prepare bounded v12 inputs from label-blind source/history facts."""
import copy
import ast
from collections import Counter
import json
from pathlib import Path
from . import citations
from .v10_inputs import _entry
from .v10_inputs import build_preloads
from .v11_inputs import select_primary_preloaded_target
from .v12_cards import POLICY, arm_input, cues, verify_arms
from .v12_context import initial_size


class AdmissionError(ValueError):
    """A source-only exclusion, never based on a security label or run outcome."""


def upgrade(common, history, case, ceiling):
    common, history = copy.deepcopy(common), copy.deepcopy(history)
    common['protocol_revision'] = POLICY
    common['v12_compression']=1
    if not common.get('preloaded_source_ranges'):
        source_root=Path(case['baseline'])/'source'
        # A planner's property/assignment group may not be a callable scope.
        # Resolve it to its current enclosing AST scope; module-only edits get
        # an explicit module target rather than silently excluding the case.
        bases=common.get('change_audit_bases',[])
        if not bases:
            bases=[{k:g[k] for k in ('path','symbol','group_id') if k in g}
                   for g in common.get('current_code_groups',[])[:1]]
        normalized=[];fallback=[]
        for base in bases:
            source=(source_root/base['path']).read_text();scopes=citations.symbols(source)
            counts=Counter(s['symbol'] for s in scopes)
            if counts[base['symbol']]==1:normalized.append(base);continue
            group=next((g for g in common.get('current_code_groups',[]) if g['path']==base['path'] and g['symbol']==base['symbol']),{})
            line=group.get('start_line',1)
            containing=[s for s in scopes if s['start_line']<=line<=s['end_line'] and counts[s['symbol']]==1]
            target=min(containing,key=lambda s:s['end_line']-s['start_line']) if containing else {
                'symbol':'<module>','start_line':1,'end_line':len(source.splitlines())}
            fallback.append(_entry(source,base['path'],target,'selected_target'))
        preloads,selection=build_preloads({**common,'change_audit_bases':normalized},source_root)
        seen={(r['path'],r['symbol']) for r in preloads}
        for row in fallback:
            if (row['path'],row['symbol']) not in seen:
                preloads.append(row);seen.add((row['path'],row['symbol']))
        common['preloaded_source_ranges'],common['preload_selection']=preloads,selection
    if not common.get('preloaded_source_ranges'):
        # Explicit admission failure rather than an ungrounded investigation.
        if not common.get('current_code_groups'):
            raise AdmissionError('No current production-code review target: changed production files deleted and no scanner-linked current symbols')
        raise ValueError('No callable selected target available for v12 preload')
    common['primary_preloaded_target'] = select_primary_preloaded_target(common, history)
    primary = common['primary_preloaded_target']
    selected=[row for row in common['preloaded_source_ranges']
              if row.get('relationship','').startswith('selected_target')]
    concrete=[row for row in selected if row['symbol']!='<module>']
    primary_row=next((row for row in selected if (row['path'],row['symbol'])==
                      (primary['path'],primary['symbol'])),{})
    # A module group records dispersed edits; it is not a useful 1,000-line
    # coaching target when exact changed callables are already available. For a
    # very large ordinary class, prefer its exact selected child. Small classes
    # remain intact for cross-method contracts (parser callbacks, form options,
    # label rendering). This rule depends only on current AST/source shape.
    descendants=[row for row in concrete if row['path']==primary['path']
                 and row['symbol'].startswith(primary['symbol']+'.')]
    if (primary['symbol']=='<module>' and concrete) or (
            len(primary_row.get('source','').splitlines())>300 and descendants):
        chosen=(descendants or concrete)[0]
        primary={'path':chosen['path'],'symbol':chosen['symbol'],
                 'selection_policy':primary['selection_policy']+'-concrete-large-scope-v1',
                 'pattern_matched':primary['pattern_matched']}
        common['primary_preloaded_target']=primary
    key = (primary['path'],primary['symbol'])
    try:ast.parse((Path(case['baseline'])/'source'/primary['path']).read_text())
    except SyntaxError as exc:
        raise AdmissionError('Primary baseline file does not parse as Python: '+primary['path']+':'+str(exc.lineno)) from exc
    common['v12_precomputed_cues'] = {a:cues(common,history,a in {'C1','C3'},a in {'C2','C3'})
                                      for a in ('C1','C2','C3')}
    # All source omissions are common to the four arms. Primary source is never
    # truncated. Exact ranges removed here are not registered as Turn-0 reads.
    rows = common['preloaded_source_ranges']
    omitted = []
    limit=min(72000,ceiling-25000)
    common['preload_selection']={**common.get('preload_selection',{}),
        'v12_omitted_preload_ranges':omitted,'initial_serialized_limit_bytes':limit,
        'retrieval':'Use read/structure for omitted bodies; only delivered exact source is registered as read.'}
    def omission(row):
        return {k:row[k] for k in ('path','symbol','start_line','end_line')}
    for row in list(rows):
        if (row['path'],row['symbol']) == key:
            continue
        if any(other is not row and other['path']==row['path'] and
               other['start_line']<=row['start_line'] and other['end_line']>=row['end_line']
               and (other['end_line']-other['start_line'] > row['end_line']-row['start_line'])
               for other in rows):
            rows.remove(row); omitted.append(omission(row))
    for group in common.get('current_code_groups',[]):
        if any(r['path']==group['path'] and r['start_line']<=group['start_line']
               and r['end_line']>=group['end_line'] for r in rows):
            group['source']=''; group['source_abbreviated']=False
        elif len(group.get('source',''))>600:
            group['source']=group['source'][:600];group['source_abbreviated']=True
    common['temporal_card_max_bytes']=min(9000,common.get('temporal_card_max_bytes',9000))
    common['flow_association_max_bytes']=2000
    def size():return max(initial_size(arm_input(common,history,a)) for a in ('C0','C1','C2','C3'))
    for row in sorted(list(rows),key=lambda r:(r.get('relationship','').startswith('selected_target'),-len(r['source']))):
        if size()<=limit:break
        if (row['path'],row['symbol'])==key:continue
        rows.remove(row);omitted.append(omission(row))
    # Remove duplicative shared flow detail last; native scanner evidence stays
    # accessible through flow(alert_id), and all alert IDs remain in the ledger.
    if size()>limit:
        flow=common.get('scanner_flow_context',{})
        common.setdefault('v12_shared_overrides',{})['scanner_flow_context']={
            'status':'deferred_to_flow_tool','reason':'shared initial context reserve',
            'full_flow_facts_archived':True,'alert_ids':[a['alert_id'] for a in common.get('scanner_alerts',[])]}
    if size()>limit:
        common['v12_compression']=2
    if size()>limit:
        common['v12_compression']=3
    for group in common.get('current_code_groups',[]):
        if not group.get('source') and not any(r['path']==group['path'] and
                r['start_line']<=group['start_line'] and r['end_line']>=group['end_line'] for r in rows):
            group['source_abbreviated']=True
    verified=verify_arms(common,history,ceiling)
    verified['primary_target']=primary
    verified['omitted_preloads']=len(omitted)
    return common,history,verified
