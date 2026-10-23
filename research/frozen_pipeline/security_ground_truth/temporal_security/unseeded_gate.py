"""Symmetric, source-bound evidence requirements for scanner-negative edits.

These checks enforce evidence completeness, not semantic truth. Official hidden
security tests remain outside the investigator and decide benchmark outcomes.
"""
import ast
import re
from . import citations

POLICY = 'scanner-negative-evidence-v3-auto-bound-consumer-review'
V9_POLICY = 'scanner-negative-v9-source-bound-invariant-and-differential-boundary'
V10_POLICY = 'scanner-negative-v10-entrypoint-or-rendering-boundary'
V11_POLICY = 'scanner-negative-v11-source-bound-refutation-and-target-reaching-rerun'


def boundary_context(hypothesis, editor, reads):
    """Distinguish a public input contract from an intermediate HTML producer.

    No benchmark identity or outcome is used. Preloaded ranges are ordinary
    source-hash-bound reads. Absence of local callers is a scope fact, not proof
    of safety; HTML producers still require downstream rendering evidence.
    """
    path = hypothesis['path']
    source = editor.text(path)
    target = hypothesis.get('target_symbol') or scope_at(source, hypothesis['line'])
    symbol = (target or {}).get('symbol', '')
    current = [s for s in citations.symbols(source) if s['symbol'] == symbol]
    snippet = '\n'.join(source.splitlines()[current[0]['start_line']-1:current[0]['end_line']]) if len(current)==1 else ''
    claim = ' '.join(str(hypothesis.get(k) or '') for k in ['mechanism','security_property','preconditions']).lower()
    leaf = symbol.rsplit('.',1)[-1].lower()
    # Use claim and producer role, not the filename (URL validators often live
    # in html.py). An HTML parser/validator is not automatically a label helper.
    html_claim = bool(re.search(r'\bxss\b|cross.site scripting|double.?escap|auto.?escap|html.{0,35}(?:escap|render|inject)|(?:escap|render|inject).{0,35}(?:html|markup)|unescaped|raw markup', claim))
    producer_role = ('label' in leaf or 'field_options' in leaf or 'help_text' in leaf
                     or ('label_from_instance' in snippet and 'return' in snippet))
    html_output = producer_role or (html_claim and bool(re.search(r'label|title|help_text|widget|render|markup|html', snippet, re.I)))
    intrinsic = bool(re.search(r'validat|authenticat|authoriz|signature|cipher|sql|\burl\b|\bast\b|filter|state|session|creat|parser|pars(?:e|ing)|canonical|delimiter|command|option|entit', claim)) and not html_output
    contract = None
    if hypothesis.get('contract_revision') == 'v12':
        from .v12_contracts import intrinsic_contract
        contract = intrinsic_contract(source, symbol, claim)
        if contract:
            html_output = False
            intrinsic = True
    digest = citations.source_hash(source)
    covered = set()
    for h, lo, hi in reads.get(path, []):
        if h == digest: covered.update(range(lo, hi+1))
    callers = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call): continue
        called = node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else None
        if called != symbol.rsplit('.',1)[-1]: continue
        scope = scope_at(source,node.lineno)
        if not scope or scope['symbol'] == symbol: continue
        key = (scope['symbol'],node.lineno)
        callers[key] = {'symbol':scope['symbol'],'call_line':node.lineno,'end_line':scope['end_line'],
                        'inspected':set(range(node.lineno,scope['end_line']+1)) <= covered}
    return {'target_symbol':symbol,'requires_html_consumer':html_output,
            **({'public_api_contract':contract} if contract else {}),
            'intrinsic_input_contract':intrinsic,'in_file_callers':list(callers.values()),
            'uninspected_in_file_callers':sum(not c['inspected'] for c in callers.values()),
            'all_in_file_callers_inspected':all(c['inspected'] for c in callers.values()),
            'source_sha256':digest,'basis':'current_source_and_claim; no_dataset_identity'}


def static_gap_context(hypothesis, proof, editor, reads):
    context = boundary_context(hypothesis, editor, reads)
    if not context['requires_html_consumer']:
        context['edit_authorized'] = context['intrinsic_input_contract'] or context['all_in_file_callers_inspected']
    else:
        consumer = proof.get('consumer') or {}
        inspected = inspected_consumers(hypothesis, editor, reads)
        context['edit_authorized'] = consumer.get('protection') == 'does_not_enforce' and any(
            c['path']==consumer.get('path') and c['symbol']==consumer.get('evidence_symbol')
            and c['source_sha256']==consumer.get('source_sha256') for c in inspected)
    return context


def scope_at(source, line):
    found = [s for s in citations.symbols(source) if s['start_line'] <= line <= s['end_line']]
    return min(found, key=lambda s: s['end_line']-s['start_line']) if found else None


def scanner_links(hypothesis, alerts, original_source):
    """An unrelated warning ID/file cannot exempt an unflagged symbol."""
    scope = scope_at(original_source, hypothesis['line'])
    matches = []
    for alert in alerts.values():
        locations = [(alert.get('path'), alert.get('line'))]
        for flow in alert.get('flow') or []:
            for thread in flow.get('threadFlows', []):
                for item in thread.get('locations', []):
                    p = item.get('location', {}).get('physicalLocation', {})
                    locations.append((p.get('artifactLocation', {}).get('uri'), p.get('region', {}).get('startLine')))
        for path, line in locations:
            if path != hypothesis['path'] or type(line) is not int:
                continue
            other = scope_at(original_source, line)
            if (scope and other and scope['symbol'] == other['symbol']) or (not scope and line == hypothesis['line']):
                matches.append(alert['alert_id']); break
    return sorted(set(matches))


def completed_check(check):
    f = check['feedback']
    return (f.get('status') == 'completed' and f.get('source_identity') == 'expected_files_match'
            and f.get('target_reached') and f.get('target_identity_resolved', True))


def observed(check, name, expected):
    values = [x.get('value') for x in check['feedback'].get('observations', []) if x.get('property') == name]
    return bool(values) and all(type(v) is bool and v is expected for v in values)


def before_control(check):
    base = (check.get('ordinary_control_program_qualified') is True and completed_check(check)
            and observed(check, 'unseeded_ordinary_control_pass', True)
            and observed(check, 'unseeded_sink_reached', True)
            and observed(check, 'unseeded_property_violated', True))
    if check.get('v10_protocol') or check.get('v11_protocol'):
        return (check.get('probe_use_qualification',{}).get('can_authorize_scanner_negative_edit') is True
                and completed_check(check))
    if not check.get('v9_protocol'):return base
    return (base and check.get('boundary_program_qualified') is True
            and check.get('consumer_context_verified') is True
            and check['feedback'].get('ordinary_target_frame_executed') is True
            and check['feedback'].get('mutated_target_frame_executed') is True
            and (not check.get('guard_preservation_required') or observed(check,'unseeded_guard_preserved',True)))


def control_program_qualified(code, property_name='unseeded_ordinary_control_pass'):
    """Reject a declared control success with no computed behavioral condition.

    This is a necessary syntactic check, not proof that a chosen control models
    the real security boundary. Endpoint substitution still needs review.
    No generated code is executed by this validator.
    """
    try:tree=ast.parse(code)
    except SyntaxError:return False
    assigned={}
    for node in ast.walk(tree):
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):assigned.setdefault(target.id,[]).append(node.value)
    def constant(node,seen=()):
        if isinstance(node,ast.Constant):return True
        if isinstance(node,ast.Name):
            return node.id not in seen and bool(assigned.get(node.id)) and all(constant(v,(*seen,node.id)) for v in assigned[node.id])
        if isinstance(node,(ast.List,ast.Tuple,ast.Set)):return all(constant(v,seen) for v in node.elts)
        if isinstance(node,ast.Dict):return all(v is not None and constant(v,seen) for v in [*node.keys,*node.values])
        if isinstance(node,ast.Compare):return constant(node.left,seen) and all(constant(v,seen) for v in node.comparators)
        if isinstance(node,ast.BoolOp):return all(constant(v,seen) for v in node.values)
        if isinstance(node,ast.BinOp):return constant(node.left,seen) and constant(node.right,seen)
        if isinstance(node,ast.UnaryOp):return constant(node.operand,seen)
        if isinstance(node,ast.IfExp):return all(constant(v,seen) for v in [node.test,node.body,node.orelse])
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'bool','str','int','float','len'}:
            return all(constant(v,seen) for v in [*node.args,*(k.value for k in node.keywords)])
        return False
    observations=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
                  and n.func.id=='tracer_observe' and len(n.args)>=2 and isinstance(n.args[0],ast.Constant)
                  and n.args[0].value==property_name]
    return bool(observations) and all(not constant(n.args[1]) for n in observations)


def after_control(gate, hypothesis_id, checks, patch_hash):
    if gate.get('v11_protocol'):
        # v11 permits the investigator to adapt setup/assertions after a repair.
        # Bind validation to the hypothesis, exact candidate, target execution,
        # and consumer boundary instead of the generated program's byte hash.
        def no_recorded_violation(check):
            values=[x.get('value') for x in check.get('feedback',{}).get('observations',[])
                    if x.get('property')=='unseeded_property_violated']
            return not values or all(type(value) is bool and value is False for value in values)
        return any(c['hypothesis_id']==hypothesis_id and c['candidate_patch_sha256']==patch_hash
                   and c.get('purpose')=='post_edit_validation'
                   and c.get('v11_protocol') and completed_check(c)
                   and c.get('probe_use_qualification',{}).get('can_authorize_scanner_negative_edit') is True
                   and no_recorded_violation(c)
                   and (not gate.get('requires_html_consumer') or c.get('consumer_context_verified'))
                   for c in checks)
    if gate.get('v10_protocol'):
        # This attests a completed rerun, not a proven security conversion.
        # Official security evaluation supplies that outcome after finalization.
        return any(c['hypothesis_id']==hypothesis_id and c['candidate_patch_sha256']==patch_hash
                   and c.get('code_sha256')==gate.get('before_check_code_sha256')
                   and c.get('v10_protocol') and completed_check(c)
                   and (not gate.get('requires_html_consumer') or c.get('consumer_context_verified'))
                   for c in checks)
    return any(c['hypothesis_id'] == hypothesis_id and c['candidate_patch_sha256'] == patch_hash
               and c.get('code_sha256') == gate.get('before_check_code_sha256')
               and c.get('ordinary_control_program_qualified') is True and completed_check(c)
               and observed(c, 'unseeded_ordinary_control_pass', True)
               and observed(c, 'unseeded_property_violated', False)
               and (not gate.get('v10_protocol') or (c.get('v10_protocol') is True
                    and c.get('consumer_context_verified') is True
                    and observed(c,'unseeded_sink_reached',True)))
               and (not gate.get('v9_protocol') or (c.get('boundary_program_qualified') is True
                    and c.get('consumer_context_verified') is True
                    and c['feedback'].get('ordinary_target_frame_executed') is True
                    and c['feedback'].get('mutated_target_frame_executed') is True
                    and observed(c,'unseeded_sink_reached',True)
                    and c.get('design_sha256')==gate.get('design_sha256'))) for c in checks)


def boundary_program_qualified(code, guarded=False):
    names=['unseeded_ordinary_control_pass','unseeded_sink_reached','unseeded_property_violated']
    if guarded:names.append('unseeded_guard_preserved')
    return all(control_program_qualified(code,name) for name in names)


def verified_consumer_context(check, hypothesis, assessment, editor, reads, *, protocol='v9'):
    """Runtime caller provenance or a source-bound inspected consumer contract.

    A generated helper or an executed child of the producer is not a caller.
    Runtime lineage is necessary evidence, not a proof of sink semantics.
    """
    if any(f.get('relationship')=='runtime_ancestor_of_target' and f.get('source_sha256')
           and (protocol in {'v10','v11'} or f.get('phase')=='mutated')
           for f in check.get('feedback',{}).get('target_caller_frames',[])):
        return True
    proof=assessment.get('static_invariant') or {}
    consumer=assessment.get('consumer_review') or proof.get('consumer') or {}
    if consumer.get('protection')!='does_not_enforce':return False
    return any(c['path']==consumer.get('path') and c['symbol']==consumer.get('evidence_symbol')
               and c['source_sha256']==consumer.get('source_sha256')
               for c in inspected_consumers(hypothesis,editor,reads))


def inspected_consumers(hypothesis,editor,reads):
    """Find observed callers in inspected source; no semantic dispatch claim.

    A read of only the producer cannot prove downstream escaping is absent.
    Require current-source reads from the call through the consumer's end, so
    reading a call site while omitting its subsequent rendering is insufficient.
    """
    target=hypothesis.get('target_symbol') or scope_at(editor.text(hypothesis['path']),hypothesis['line'])
    if not target:return []
    leaf=target['symbol'].split('.')[-1];found=[]
    for path in sorted(editor.read_paths|{hypothesis['path']}):
        source=editor.text(path);digest=citations.source_hash(source)
        try:tree=ast.parse(source)
        except SyntaxError:continue
        for call in ast.walk(tree):
            if not isinstance(call,ast.Call):continue
            called=call.func.id if isinstance(call.func,ast.Name) else call.func.attr if isinstance(call.func,ast.Attribute) else None
            if called!=leaf:continue
            consumer=scope_at(source,call.lineno)
            if not consumer or (path==hypothesis['path'] and consumer['symbol']==target['symbol']):continue
            covered=set()
            for h,lo,hi in reads.get(path,[]):
                if h==digest:covered.update(range(lo,hi+1))
            if not set(range(call.lineno,consumer['end_line']+1))<=covered:continue
            found.append({'path':path,'symbol':consumer['symbol'],'start_line':call.lineno,
                'end_line':consumer['end_line'],'source_sha256':digest,
                'quote':'\n'.join(source.splitlines()[call.lineno-1:consumer['end_line']]),
                'relationship':'inspected_syntactic_caller; dispatch_and_security_semantics_not_proven'})
    return found


def automatic_gate(hypothesis,assessment,editor,reads,checks,patch_hash,requested=None,*,strict=False,protocol='v9'):
    """Reuse bound evidence; never ask the model to retype hashes/anchor arrays.

    Static support is recorded even before consumer inspection. Editing remains
    blocked until inspection or a qualified before/after dynamic witness exists.
    """
    policy=V11_POLICY if protocol=='v11' else V10_POLICY if protocol=='v10' else V9_POLICY if strict else POLICY
    def protocol_check(c):
        if not strict:return True
        if protocol=='v11':return bool(c.get('v11_protocol'))
        return bool(c.get('v10_protocol')) if protocol=='v10' else bool(c.get('v9_protocol'))
    dynamic=[c for c in checks if c['hypothesis_id']==hypothesis['hypothesis_id']
             and protocol_check(c) and c['candidate_patch_sha256']==patch_hash and before_control(c)]
    if dynamic:
        return {'policy':policy,'mode':'dynamic_control','candidate_patch_sha256':patch_hash,
                'before_check_code_sha256':dynamic[-1]['code_sha256'],'binding_owner':'harness',
                **({'v11_protocol':True,'requires_html_consumer':dynamic[-1].get('requires_html_consumer',True),
                    'validation_scope':'completed_target_reaching_rerun_on_exact_candidate; probe_source_may_change'} if protocol=='v11' else
                   {'v10_protocol':True,'requires_html_consumer':dynamic[-1].get('requires_html_consumer',True),
                    'validation_scope':'completed_target_reaching_rerun; security_property_not_automatically_proven'} if protocol=='v10' else
                   {'v9_protocol':True,'design_sha256':dynamic[-1]['design_sha256']} if strict else {}),
                'independently_verified':False}
    citation=assessment.get('citation')
    consumers=inspected_consumers(hypothesis,editor,reads)
    if protocol in {'v10','v11'}:
        proof=assessment.get('static_invariant') or {}
        context=static_gap_context(hypothesis,proof,editor,reads)
        if citation and proof.get('enforcement_kind') in {'missing_boundary_guard','sanitizing_transformation'} and context['edit_authorized']:
            return {'policy':policy,'mode':'static_chain','edit_authorized':True,
                    **({'v11_protocol':True} if protocol=='v11' else {'v10_protocol':True}),
                    'candidate_patch_sha256':patch_hash,'binding_owner':'harness','independently_verified':False,
                    'static_invariant':proof,'boundary_context':context,
                    'input_trust_boundary':hypothesis['preconditions'],'violated_property':hypothesis['security_property'],
                    'path_to_sink':hypothesis['mechanism'],'source_anchors':[citation,*consumers[:6]]}
    if strict:
        proof=assessment.get('static_invariant') or {}
        consumer=proof.get('consumer') or {}
        consumers=[c for c in consumers if c['path']==consumer.get('path') and c['symbol']==consumer.get('evidence_symbol')
                   and c['source_sha256']==consumer.get('source_sha256')]
        if proof.get('enforcement_kind')!='missing_boundary_guard' or consumer.get('protection')!='does_not_enforce':consumers=[]
    if not citation or not consumers:
        return {'policy':policy,'mode':'awaiting_downstream_inspection','edit_authorized':False,
                'candidate_patch_sha256':patch_hash,
                'reason':'Inspect the current caller/consumer through downstream rendering or run a qualified ordinary-input/boundary check.',
                'next_action':{'action':'search','text':(hypothesis.get('target_symbol') or {}).get('symbol','').split('.')[-1]+'('}}
    target_citation=citations.resolve(editor.text(hypothesis['path']),{'line_range':[hypothesis['line'],hypothesis['line']]},hypothesis,[])
    return {'policy':policy,'mode':'static_chain','edit_authorized':True,'binding_owner':'harness',
            **({'v11_protocol':True,'static_invariant':assessment['static_invariant']} if protocol=='v11' else
               {'v10_protocol':True,'static_invariant':assessment['static_invariant']} if protocol=='v10' else
               {'v9_protocol':True,'static_invariant':assessment['static_invariant']} if strict else {}),
            'candidate_patch_sha256':patch_hash,'independently_verified':False,
            'input_trust_boundary':hypothesis['preconditions'],
            'violated_property':hypothesis['security_property'],
            'path_to_sink':hypothesis['mechanism'],
            'downstream_review':assessment['reason'],
            'source_anchors':[{'path':hypothesis['path'],**target_citation},citation,*consumers[:6]],
            'consumer_evidence_count':len(consumers)}
