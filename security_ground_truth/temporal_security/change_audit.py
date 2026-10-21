"""Extractive change/intent cards. No model, oracle, reference patch or labels.

This extractor contains patch-derived information. In v9 it is available only
in C1/C3. The explicit legacy test adapter preserves the archived v8 contract.
"""
import ast
import copy
import hashlib
import json
import re

POLICY='change-intent-omission-v3-sibling-guards'
BOUNDARY_PROMPT=('Identify the attacker-controlled input and omitted input shapes or boundary cases in this change. '
    'Follow the value into its consumer, check downstream protections, and distinguish functional assumptions '
    'from security guarantees. Ask what the implemented checks fail to cover; do not infer a vulnerability from absence alone.')


def boundary_questions(group):
    """Generic syntax questions attached to patch-derived temporal cards."""
    calls=' '.join(c['callee'] for c in group.get('calls',[]));name=group['symbol'];questions=[]
    if re.search(r'\b(Popen|run|_run|check_call|check_output|exec|spawn)|_run_for_',calls):
        questions.append('At the process boundary, distinguish shell parsing from argv option parsing and confidentiality. Can data be interpreted as an option? Are sensitive values visible in arguments or logs? Does the real consumer accept the chosen representation?')
    if re.search(r'sql|query|select|cte',calls+' '+name,re.I):
        questions.append('Does classification inspect nested statements and side effects, or only the outer statement/token? Compare authorized read-only behavior with nested or compound input shapes.')
    if re.search(r'bytes2int|int2bytes|decrypt|signature|verify',calls+' '+name,re.I):
        questions.append('Does decoding/canonicalization discard representation information that validation needs, such as original byte length or leading bytes? Check each input path separately.')
    if re.search(r'strip|parser|html|feed',calls+' '+name,re.I):
        questions.append('Check malformed input and resource bounds in the implementation that actually exists. If processing repeats, establish progress/termination; if it is single-pass, do not assume a loop defect.')
    questions.append('Check an ordinary valid input and a distinct omitted boundary condition at the downstream consumer. Prior functional success does not establish the security property.')
    return questions


def current_facts(source,group):
    changed=set(group.get('changed_lines',[]));rows=[]
    try:tree=ast.parse(source)
    except SyntaxError:return {'status':'unparseable','nodes':[]}
    for node in ast.walk(tree):
        if not isinstance(node,(ast.Call,ast.If,ast.While,ast.Assert,ast.Return,ast.Raise,ast.Assign,ast.With)):continue
        if not group['start_line']<=node.lineno<=group['end_line']:continue
        if node.lineno not in changed:continue
        if isinstance(node,(ast.If,ast.While,ast.Assert)):text=ast.unparse(node.test)
        elif isinstance(node,ast.With):text=', '.join(ast.unparse(i.context_expr) for i in node.items)
        else:text=ast.get_source_segment(source,node) or ast.unparse(node)
        rows.append({'kind':type(node).__name__,'line':node.lineno,'end_line':node.end_lineno,
                     'syntax':text[:650],'syntax_clipped':len(text)>650})
    rows.sort(key=lambda x:(x['line'],x['kind']))
    return {'status':'current_patch_intersection','nodes':rows[:10],'omitted_nodes':max(0,len(rows)-10),
        'attribution':'Current syntax intersecting added/replacement lines, not reconstructed historical AST operations.'}


def linked_temporal(record,path,symbol):
    if record.get('path')!=path:return False
    return (record.get('symbol_filter')==symbol
        or any(a.get('current_symbol')==symbol for a in record.get('current_symbol_anchors',[]))
        or any(h.get('symbol')==symbol for h in record.get('symbol_hints',[])))


def cards(common,history,temporal,rationale,*,max_bytes=22000):
    result=[];used=0;omitted=0
    bases=common.get('change_audit_bases',[])
    prompts={}
    for base in bases:
        for prompt in base.get('current_syntax_boundary_questions',[]):
            prompts[hashlib.sha256(prompt.encode()).hexdigest()[:12]]=prompt
    allowance=max(500,(max_bytes-len(json.dumps(prompts).encode())-800)//max(1,len(bases)))
    for base in bases:
        base=copy.deepcopy(base)
        base['boundary_prompt_ids']=[hashlib.sha256(p.encode()).hexdigest()[:12] for p in base.pop('current_syntax_boundary_questions',[])]
        facts=base.get('patch_facts',{});nodes=facts.get('nodes',[])
        for node in nodes:
            if len(node['syntax'])>180:node['syntax']=node['syntax'][:180];node['syntax_clipped']=True
        kept=nodes[:3]
        while len(json.dumps({**base,'patch_facts':{**facts,'nodes':kept}}).encode())>allowance//2 and kept:
            kept=kept[:-1]
        if facts:
            facts['nodes']=kept;facts['omitted_nodes']=facts.get('omitted_nodes',0)+len(nodes)-len(kept)
        path,symbol=base['path'],base['symbol']
        sibling_ids=[p['comparison_id'] for p in common.get('sibling_change_comparisons',{}).get('pairs',[])
                     if base.get('group_id') in [p['left']['group_id'],p['right']['group_id']]]
        card={**base,'sibling_guard_comparison_ids':sibling_ids,
              'temporal_changes':{'status':'withheld_by_arm'},'recorded_intent':{'status':'withheld_by_arm'}}
        if temporal:
            channels={}
            for channel in ['agent','git']:
                block=(history.get('temporal') or {}).get(channel,{})
                matched=[r for r in block.get('records',[]) if linked_temporal(r,path,symbol)]
                channels[channel]={'status':'available' if matched else block.get('status','not_available'),
                    'symbol_records_found':len(matched),'events':[{
                        'event_id':r['event_id'],'source_fidelity':r.get('source_fidelity'),
                        'continuous_transition':r.get('continuous_transition'),
                        'guard_deltas':r.get('guard_deltas',{'status':'not_recorded'}),
                        'fallback_deltas':r.get('fallback_deltas',{'status':'not_recorded'}),
                        'symbol_hints':r.get('symbol_hints',[])[:1],
                        'node_changes':r.get('node_changes',[])[:1]} for r in matched[:1]]}
            card['temporal_changes']=channels
        if rationale:
            exact=[];file_only=[]
            # The exposed list is chronological for reading. Cards instead
            # prioritize edit-linked assumptions/corrections, not the first
            # generic "let me inspect" mention of the function.
            events=(history.get('rationale') or {}).get('events',[])
            def intent_rank(event):
                links=[l for l in event.get('links',[]) if l.get('path')==path]
                edited=any(symbol in l.get('edited_symbol_mentions',[]) or any(
                    a.get('current_symbol')==symbol for a in l.get('current_symbol_anchors',[])) for l in links)
                return (edited,event.get('retrieval_score',0),event.get('message_index',0))
            for event in sorted(events,key=intent_rank,reverse=True):
                links=[l for l in event.get('links',[]) if l.get('path')==path]
                if not links:continue
                linked=symbol in event.get('mentioned_target_symbols',[]) or any(
                    a.get('current_symbol')==symbol for l in links for a in l.get('current_symbol_anchors',[])) or any(
                    symbol in l.get('edited_symbol_mentions',[]) for l in links)
                value={k:event[k] for k in ['event_id','span_id','text','start_char','end_char'] if k in event}
                value['association']='symbol_mention_or_edit_anchor' if linked else 'file_only_not_symbol_intent'
                (exact if linked else file_only).append(value)
            card['recorded_intent']={'status':'available' if exact or file_only else 'no_recorded_symbol_intent',
                'excerpts':(exact or file_only)[:1]}
        size=len(json.dumps(card).encode())
        if size>allowance:
            card['detail_abbreviated']=True
            for channel in ['agent','git']:
                block=card['temporal_changes'].get(channel,{})
                for event in block.get('events',[]):
                    event.pop('node_changes',None)
                    event['symbol_hints']=[{'hint':h['hint'][:180],'clipped':len(h['hint'])>180} for h in event.get('symbol_hints',[])]
            for excerpt in card['recorded_intent'].get('excerpts',[]):
                excerpt['text']=excerpt['text'][:180];excerpt['end_char']=excerpt.get('start_char',0)+len(excerpt['text'])
                excerpt['abbreviated_in_card']=True
        if len(json.dumps(card).encode())>allowance:
            for channel in ['agent','git']:
                block=card['temporal_changes'].get(channel,{})
                block['events']=[{'event_id':e['event_id'],'detail_location':'temporal_history'} for e in block.get('events',[])]
            card['recorded_intent']['excerpts']=[{'event_id':e['event_id'],'span_id':e.get('span_id'),
                'detail_location':'developer_rationale'} for e in card['recorded_intent'].get('excerpts',[])]
        if len(json.dumps(card).encode())>allowance:
            # Preserve every selected identity and historical link when a large
            # class/body has more syntax than can fit in the initial prompt.
            card={k:v for k,v in card.items() if k in {'path','symbol','group_id',
                'sibling_guard_comparison_ids','temporal_changes','recorded_intent'}}
            card['detail_abbreviated']=True
        size=len(json.dumps(card).encode())
        if used+size>max_bytes:raise ValueError('Change cards exceed budget; reduce shared source detail, never silently remove later targets')
        result.append(card);used+=size
    return {'policy':POLICY,'cards':result,'omitted_cards':omitted,'bytes_used':used,
            'boundary_question':BOUNDARY_PROMPT,'boundary_review_prompts':prompts,
            'rationale_rule':'Quoted implementation assumptions are claims to verify, not facts or authenticated private reasoning.',
            'labels_used':False,'synthesis':'deterministic extraction; no model-generated intent or vulnerability labels'}
