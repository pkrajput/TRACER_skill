"""Generic sibling-change comparisons from visible code; no benchmark labels."""
import ast
import copy
import hashlib
import json
import re

QUESTION=('Compare the observed guards and validation calls across these related changed symbols. '
          'Does a sibling require analogous input-representation validation, or do different contracts '
          'and downstream checks explain the asymmetry? Absence of a matching guard is a review question, '
          'not proof of a vulnerability. Verify the real consumer before editing.')


def profile(source, group):
    """Inspect the whole current function, excluding nested definitions."""
    found=[]
    def find(node, parents=()):
        for child in ast.iter_child_nodes(node):
            if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                name='.'.join((*parents,child.name))
                if name==group['symbol'] and group['start_line']<=child.lineno<=group['end_line']:found.append(child)
                find(child,(*parents,child.name))
            else:find(child,parents)
    find(ast.parse(source))
    if len(found)!=1 or not isinstance(found[0],(ast.FunctionDef,ast.AsyncFunctionDef)):return None
    function=found[0];arguments={a.arg for a in [*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs]}
    class NormalizeInputs(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Name(id='__input__',ctx=node.ctx),node) if node.id in arguments-{'self','cls'} else node
    guards=[];calls=[]
    def walk(node):
        if node is not function and isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):return
        if isinstance(node,(ast.If,ast.Assert,ast.While)):
            expression=ast.unparse(node.test)
            guards.append({'line':node.lineno,'expression':expression,
                'shape':ast.dump(NormalizeInputs().visit(copy.deepcopy(node.test)),include_attributes=False),
                'line_modified':node.lineno in group.get('changed_lines',[])})
        if isinstance(node,ast.Call):calls.append(ast.unparse(node.func))
        for child in ast.iter_child_nodes(node):walk(child)
    walk(function)
    return {'path':group['path'],'symbol':group['symbol'],'group_id':group['group_id'],
            'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'guards':guards,'calls':sorted(set(calls)),
            'validation_calls':sorted({c for c in calls if re.search(r'validat|saniti|escap|authoriz|check_',c,re.I)})}


def comparisons(profiles, max_bytes=4200):
    profiles=[p for p in profiles if p];candidates=[];pairs=[];used=0;omitted=0
    for i,left in enumerate(profiles):
        for right in profiles[i+1:]:
            same_file=left['path']==right['path']
            same_class='.' in left['symbol'] and left['symbol'].rsplit('.',1)[0]==right['symbol'].rsplit('.',1)[0]
            if not (same_file or same_class):continue
            ls={g['shape'] for g in left['guards']};rs={g['shape'] for g in right['guards']}
            lg=[g for g in left['guards'] if g['shape'] not in rs];rg=[g for g in right['guards'] if g['shape'] not in ls]
            lc=sorted(set(left['validation_calls'])-set(right['validation_calls']))
            rc=sorted(set(right['validation_calls'])-set(left['validation_calls']))
            row={'comparison_id':left['group_id']+':'+right['group_id'],
                 'asymmetry_observed':bool(lg or rg or lc or rc),
                 'relationship':'same_class_name_across_changed_symbols' if same_class else 'same_changed_file',
                 'left':{k:left[k] for k in ['path','symbol','group_id']},
                 'right':{k:right[k] for k in ['path','symbol','group_id']}}
            for side,guards,validations in [('left',lg,lc),('right',rg,rc)]:
                row[side].update(unmatched_guard_examples=[{k:g[k] for k in ['line','expression','line_modified']} for g in guards[:2]],
                    unmatched_guards_total=len(guards),validation_calls_only_here=validations[:3])
            candidates.append(row)
    covered=set()
    while candidates:
        candidates.sort(key=lambda r:(sum(r[s]['group_id'] in covered for s in ['left','right']),not r['asymmetry_observed']))
        row=candidates.pop(0);size=len(json.dumps(row).encode())
        if used+size>max_bytes:omitted+=1;continue
        pairs.append(row);used+=size;covered.update(row[s]['group_id'] for s in ['left','right'])
    return {'basis':'current_source_only_same_for_all_arms','pairs':pairs,'pairs_omitted_by_budget':omitted,
            'question':QUESTION,'guard_match':'AST shape with input-parameter names normalized; syntax only, not equivalent semantics'}


def temporal_support(comparison, history):
    """Attach separate history links, never turn current guards into past edits."""
    from .change_audit import linked_temporal
    result={}
    for side in ['left','right']:
        target=comparison[side];channels={}
        for channel in ['agent','git']:
            block=history.get('temporal',{}).get(channel,{})
            records=[r for r in block.get('records',[]) if linked_temporal(r,target['path'],target['symbol'])]
            channels[channel]={'event_ids':[r['event_id'] for r in records[:3]],
                'status':'available' if records else block.get('status','not_available')}
        result[side]=channels
    return result
