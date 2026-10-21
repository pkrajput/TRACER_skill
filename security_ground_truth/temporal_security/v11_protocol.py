"""v11 evidence contracts layered on the frozen v10 probe protocol.

v11 keeps v10's source/read binding and dynamic-evidence limits, while adding
bounded ways to clear stock-SAST non-sinks and loop-local rejecting guards.
"""
from __future__ import annotations

import ast

from . import citations
from . import unseeded_gate
from . import v10_protocol
from .v9_protocol import negative_probe_reason


POLICY = 'v11-refutation-read-coaching-refined-cues'

# The wire schema remains compatible with v10.  A scanner-linked attribute,
# import, or call is normalized to ``non_security_construct`` in the archived
# assessment only after the harness verifies its current source shape.
STATIC_INVARIANT = v10_protocol.STATIC_INVARIANT
bound_read = v10_protocol.bound_read
consumer_review = v10_protocol.consumer_review
probe_metadata = v10_protocol.probe_metadata
probe_use_qualification = v10_protocol.probe_use_qualification
register_preloaded_reads = v10_protocol.register_preloaded_reads


def _calls_in_range(source, lo, hi):
    tree = ast.parse(source)
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and lo <= getattr(node, 'lineno', 0) <= hi]


def _call_name(call):
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        try:
            return ast.unparse(call.func)
        except Exception:
            return call.func.attr
    return ''


def _construct_kind(source, lo, hi):
    """Classify the cited syntax for the narrow stock-SAST refutation route."""
    tree = ast.parse(source)
    nodes = []
    for node in ast.walk(tree):
        start = getattr(node, 'lineno', 0)
        end = getattr(node, 'end_lineno', start)
        if start and start <= hi and end >= lo:
            nodes.append(node)
    if any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in nodes):
        return 'module_import'
    if any(isinstance(node, ast.Call) for node in nodes):
        return 'api_call'
    if any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) for node in nodes):
        return 'attribute_access'
    return None


def _assessment_evidence(editor, hypothesis, assessment, reads):
    proof = assessment.get('static_invariant') or {}
    location = proof.get('evidence')
    if isinstance(location, dict):
        return bound_read(editor, location, hypothesis, reads)
    start = assessment.get('evidence_start_line')
    end = assessment.get('evidence_end_line', start)
    if assessment.get('line_range'):
        start, end = assessment['line_range']
    if start is not None:
        return bound_read(editor, {
            'path': assessment.get('path') or hypothesis['path'],
            'line_range': [start, end],
        }, hypothesis, reads)
    resolved = citations.resolve_in_editor(editor, assessment, hypothesis, reads)
    if not resolved:
        raise ValueError('Stock-SAST refutation needs a current cited attribute, import, or API call')
    covered = set()
    for digest, lo, hi in reads.get(resolved['path'], []):
        if digest == resolved['source_sha256']:
            covered.update(range(lo, hi + 1))
    wanted = set(range(resolved['evidence_start_line'], resolved['evidence_end_line'] + 1))
    if not wanted <= covered:
        raise ValueError('Read the cited stock-SAST construct on the current candidate before refuting it')
    return resolved


def _stock_sast_refutation(editor, hypothesis, assessment, reads, evidence=None):
    """Allow a source-bound API/non-sink explanation for an actually linked alert."""
    if not hypothesis.get('scanner_linked_ids'):
        return None
    reason = assessment.get('reason', '')
    proof = assessment.get('static_invariant') or {}
    coverage = proof.get('coverage_argument') or reason
    if negative_probe_reason(reason) or negative_probe_reason(coverage):
        raise ValueError('A probe execution cannot refute a hypothesis. Use a current static API/non-sink argument.')
    evidence = evidence or _assessment_evidence(editor, hypothesis, assessment, reads)
    linked_locations = hypothesis.get('scanner_linked_locations') or [{
        'path': hypothesis['path'], 'line': hypothesis['line']}]
    if not any(
            row.get('path') == evidence['path']
            and isinstance(row.get('line'), int)
            and evidence['evidence_start_line'] <= row['line'] <= evidence['evidence_end_line']
            for row in linked_locations):
        return None
    source = editor.text(evidence['path'])
    construct = _construct_kind(source, evidence['evidence_start_line'], evidence['evidence_end_line'])
    if not construct:
        return None
    return {
        'invariant': proof.get('invariant') or 'The cited stock-SAST construct is not the claimed dangerous sink',
        'enforcement_kind': 'non_security_construct',
        'evidence': evidence,
        'consumer': None,
        'coverage_argument': coverage,
        'construct_kind': construct,
        'scanner_linked_ids': list(hypothesis['scanner_linked_ids']),
        'binding_owner': 'harness',
        'qualification': 'source_bound_stock_sast_construct_refutation_not_independent_ground_truth',
    }


def static_invariant(editor, hypothesis, assessment, reads):
    """Validate v11 static evidence without inheriting v10's rejection traps."""
    proof = assessment.get('static_invariant')
    decision = assessment['decision']

    # Models sometimes retain the prior gap object while changing their
    # assessment.  It has no meaning outside supported and must not turn an
    # inconclusive assessment into an invalid action.
    if isinstance(proof, dict) and proof.get('enforcement_kind') == 'missing_boundary_guard' and decision != 'supported':
        if decision == 'inconclusive':
            return None
        refutation = _stock_sast_refutation(editor, hypothesis, assessment, reads)
        if refutation:
            return refutation
        # The ordinary assessment citation is still validated by engine.run.
        # Do not let an obsolete gap payload override that current evidence.
        return None

    if not isinstance(proof, dict):
        if decision == 'refuted':
            refutation = _stock_sast_refutation(editor, hypothesis, assessment, reads)
            if refutation:
                return refutation
            raise ValueError('A probe execution cannot refute a hypothesis. Refutation requires current source-bound evidence.')
        raise ValueError('Static invariant-gap support requires static_invariant')
    for field in ['invariant', 'coverage_argument']:
        if not isinstance(proof.get(field), str) or not proof[field].strip():
            raise ValueError('Static invariant needs ' + field)
    kind = proof.get('enforcement_kind')
    allowed = {'rejecting_guard', 'neutralizing_consumer', 'sanitizing_transformation', 'missing_boundary_guard'}
    if kind not in allowed:
        raise ValueError('Unknown static invariant enforcement kind')
    if decision == 'refuted' and (negative_probe_reason(assessment.get('reason', ''))
                                  or negative_probe_reason(proof['coverage_argument'])):
        raise ValueError('A probe execution cannot refute a hypothesis. Use inconclusive, or give a static-only enforcement argument.')

    evidence = bound_read(editor, proof.get('evidence'), hypothesis, reads)
    source = editor.text(evidence['path'])
    lo, hi = evidence['evidence_start_line'], evidence['evidence_end_line']
    tree = ast.parse(source)
    nodes = [node for node in ast.walk(tree) if lo <= getattr(node, 'lineno', 0) <= hi]

    # Stock scanners also report API-shape concerns which have no rejecting
    # branch.  Keep this exception tied to the alert's actual source scope.
    if decision == 'refuted':
        refutation = _stock_sast_refutation(editor, hypothesis, assessment, reads, evidence=evidence)
        if refutation:
            return refutation

    if kind == 'rejecting_guard' and not any(
            isinstance(node, ast.Assert) or (isinstance(node, ast.If) and any(
                isinstance(child, (ast.Raise, ast.Return, ast.Continue, ast.Break))
                for child in ast.walk(node))) for node in nodes):
        raise ValueError('Refutation needs an explicit rejecting guard/assertion or a cited sanitizing transformation')
    if kind in {'neutralizing_consumer', 'sanitizing_transformation'}:
        calls = _calls_in_range(source, lo, hi)
        if not calls:
            raise ValueError('Transformation evidence must cite the current transformation call')
        names = {_call_name(call) for call in calls}
        if any(name == 'os.path.join' or name.endswith('.path.join') for name in names):
            raise ValueError('os.path.join joins path components but does not normalize or collapse .. segments; it cannot establish traversal refutation')
        if kind == 'neutralizing_consumer':
            if not any(isinstance(node, ast.Return) and isinstance(node.value, ast.Call) for node in nodes):
                raise ValueError('Neutralizing-consumer evidence must include its returned transformation')
            target = (hypothesis.get('target_symbol') or {}).get('symbol')
            if evidence['path'] == hypothesis['path'] and evidence['evidence_symbol'] == target:
                raise ValueError('Cite the actual downstream neutralizing consumer, outside the target producer')

    consumer = None
    if proof.get('consumer') is not None:
        consumer = consumer_review(editor, proof['consumer'], hypothesis, reads)
    if kind == 'missing_boundary_guard':
        if decision != 'supported':
            raise AssertionError('non-supported invariant gaps are cleared above')
        context = unseeded_gate.static_gap_context(hypothesis, {**proof, 'consumer': consumer}, editor, reads)
        if not context['edit_authorized']:
            raise ValueError('Inspect the downstream rendering consumer for an HTML producer, or the remaining in-file callers for this non-input contract')
        target = hypothesis.get('target_symbol')
        if not target:
            raise ValueError('Review the entire target symbol before claiming an AST invariant gap')
        digest = citations.source_hash(editor.text(hypothesis['path']))
        coverage = set()
        for current_digest, read_lo, read_hi in reads.get(hypothesis['path'], []):
            if current_digest == digest:
                coverage.update(range(read_lo, read_hi + 1))
        current = [scope for scope in citations.symbols(editor.text(hypothesis['path']))
                   if scope['symbol'] == target['symbol']]
        if len(current) != 1 or not set(range(current[0]['start_line'], current[0]['end_line'] + 1)) <= coverage:
            raise ValueError('Read the full current target symbol; a narrow quote cannot establish absence of a boundary guard')
    return {**proof, 'evidence': evidence, 'consumer': consumer, 'binding_owner': 'harness',
            'qualification': 'source_bound_structural_evidence_not_semantic_proof'}


def bind_module_import_target(source, line, preferred_symbols=()):
    """Bind a module import warning to a unique/preferred function that uses it."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    imports = [node for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom))
               and node.lineno <= line <= getattr(node, 'end_lineno', node.lineno)]
    if len(imports) != 1:
        return None
    statement = imports[0]
    bound_names = set()
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            bound_names.add(alias.asname or alias.name.split('.')[0])
    else:
        for alias in statement.names:
            if alias.name != '*':
                bound_names.add(alias.asname or alias.name)
    if not bound_names:
        return None
    candidates = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in bound_names):
            continue
        scope = unseeded_gate.scope_at(source, node.lineno)
        if scope:
            candidates[scope['symbol']] = scope
    for symbol in preferred_symbols:
        if symbol in candidates:
            return {**candidates[symbol], 'binding_reason': 'module_import_preloaded_consumer'}
    if len(candidates) == 1:
        scope = next(iter(candidates.values()))
        return {**scope, 'binding_reason': 'module_import_unique_consumer'}
    return None


SYSTEM = v10_protocol.SYSTEM.replace(
    'Rerun the same program after a dynamic-supported edit and validate functionality;',
    'Rerun a completed target-reaching probe after a dynamic-supported edit and validate functionality;'
) + '''
v11 refutation and read discipline: An if-branch ending in continue or break is a rejecting guard for the current loop item, just like return or raise rejects the current function path. If an inconclusive/refuted action accidentally retains a missing_boundary_guard object, that stale gap object is ignored. A source-bound refutation of an actually linked stock SAST warning may instead cite the warned attribute access, module import, or API call and explain why that construct is a property/non-sink/safe API rather than a dangerous operation; it does not need an artificial if/raise guard. Module-level imports may be bound by the harness to a unique preloaded consuming function. The highest-priority changed target and its callers are already in the initial evidence. After three exploratory read actions, further reads of files already preloaded are blocked until you record and assess a hypothesis on that primary target. A post-edit probe may adapt setup/assertions, but it must complete, reach the same current target on the final patch, preserve any required consumer context, and must not report the security property as still violated.'''
