"""v10 evidence contracts: execute normal probes, qualify their use afterward.

The module intentionally leaves the frozen v9 contract untouched.  Dynamic
execution is diagnostic evidence only: it can support a repair when it reaches
the real boundary, but it can never refute a hypothesis.
"""
from __future__ import annotations

import ast
import hashlib
import json

from . import citations
from . import unseeded_gate
from .v9_protocol import CONSUMER, LOCATION, negative_probe_reason

STRING = {'type': 'string'}
STATIC_INVARIANT = {
    'type': 'object', 'additionalProperties': False,
    'required': ['invariant', 'enforcement_kind', 'evidence', 'consumer', 'coverage_argument'],
    'properties': {
        'invariant': STRING,
        'enforcement_kind': {'type': 'string', 'enum': [
            'rejecting_guard', 'neutralizing_consumer', 'sanitizing_transformation',
            'missing_boundary_guard']},
        'evidence': LOCATION,
        'consumer': {'anyOf': [CONSUMER, {'type': 'null'}]},
        'coverage_argument': STRING,
    },
}


def bound_read(editor, value, hypothesis, reads):
    """Bind a citation to current source and an actual or pre-registered read."""
    if not isinstance(value, dict) or not value.get('path') or not value.get('line_range'):
        raise ValueError('Static invariant evidence needs a current path and line_range')
    bound = citations.resolve_in_editor(editor, value, hypothesis, reads)
    covered = set()
    for digest, lo, hi in reads.get(bound['path'], []):
        if digest == bound['source_sha256']:
            covered.update(range(lo, hi + 1))
    wanted = set(range(bound['evidence_start_line'], bound['evidence_end_line'] + 1))
    if not wanted <= covered:
        raise ValueError('Read the cited invariant/consumer range on the current candidate before assessing it')
    return bound


def consumer_review(editor, value, hypothesis, reads):
    bound = bound_read(editor, value, hypothesis, reads)
    if value.get('protection') not in {'enforced', 'does_not_enforce'} or not value.get('explanation', '').strip():
        raise ValueError('Consumer review needs a protection conclusion and source-grounded explanation')
    return {**bound, 'protection': value['protection'], 'explanation': value['explanation']}


def _calls_in_range(source, lo, hi):
    tree = ast.parse(source)
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and lo <= getattr(n, 'lineno', 0) <= hi]


def _call_name(call):
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        try:
            return ast.unparse(call.func)
        except Exception:
            return call.func.attr
    return ''


def static_invariant(editor, hypothesis, assessment, reads):
    """Validate source-bound static proof, including transformation evidence."""
    proof = assessment.get('static_invariant')
    if not isinstance(proof, dict):
        if assessment.get('decision') == 'refuted':
            raise ValueError('A probe execution cannot refute a hypothesis. Refutation requires a source-bound static guard or transformation.')
        raise ValueError('Static invariant-gap support requires static_invariant')
    for field in ['invariant', 'coverage_argument']:
        if not isinstance(proof.get(field), str) or not proof[field].strip():
            raise ValueError('Static invariant needs ' + field)
    kind = proof.get('enforcement_kind')
    decision = assessment['decision']
    allowed = {'rejecting_guard', 'neutralizing_consumer', 'sanitizing_transformation', 'missing_boundary_guard'}
    if kind not in allowed:
        raise ValueError('Unknown static invariant enforcement kind')
    if decision == 'refuted':
        if negative_probe_reason(assessment.get('reason', '')) or negative_probe_reason(proof['coverage_argument']):
            raise ValueError('A probe execution cannot refute a hypothesis. Use inconclusive, or give a static-only enforcement argument.')
        if kind == 'missing_boundary_guard':
            raise ValueError('A missing guard cannot refute a security hypothesis')

    evidence = bound_read(editor, proof.get('evidence'), hypothesis, reads)
    source = editor.text(evidence['path'])
    lo, hi = evidence['evidence_start_line'], evidence['evidence_end_line']
    tree = ast.parse(source)
    nodes = [n for n in ast.walk(tree) if lo <= getattr(n, 'lineno', 0) <= hi]
    if kind == 'rejecting_guard' and not any(
            isinstance(n, ast.Assert) or (isinstance(n, ast.If) and any(
                isinstance(x, (ast.Raise, ast.Return)) for x in ast.walk(n))) for n in nodes):
        raise ValueError('Refutation needs an explicit rejecting guard/assertion or a cited sanitizing transformation')
    if kind in {'neutralizing_consumer', 'sanitizing_transformation'}:
        calls = _calls_in_range(source, lo, hi)
        if not calls:
            raise ValueError('Transformation evidence must cite the current transformation call')
        names = {_call_name(call) for call in calls}
        if any(name == 'os.path.join' or name.endswith('.path.join') for name in names):
            raise ValueError('os.path.join joins path components but does not normalize or collapse .. segments; it cannot establish traversal refutation')
        if kind == 'neutralizing_consumer':
            if not any(isinstance(n, ast.Return) and isinstance(n.value, ast.Call) for n in nodes):
                raise ValueError('Neutralizing-consumer evidence must include its returned transformation')
            target = hypothesis.get('target_symbol', {}).get('symbol')
            if evidence['path'] == hypothesis['path'] and evidence['evidence_symbol'] == target:
                raise ValueError('Cite the actual downstream neutralizing consumer, outside the target producer')

    consumer = None
    if proof.get('consumer') is not None:
        consumer = consumer_review(editor, proof['consumer'], hypothesis, reads)
    if kind == 'missing_boundary_guard':
        if decision != 'supported':
            raise ValueError('Invariant-gap evidence supports a defect; it cannot establish refutation')
        context = unseeded_gate.static_gap_context(hypothesis, {**proof,'consumer':consumer}, editor, reads)
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
        current = [s for s in citations.symbols(editor.text(hypothesis['path'])) if s['symbol'] == target['symbol']]
        if len(current) != 1 or not set(range(current[0]['start_line'], current[0]['end_line'] + 1)) <= coverage:
            raise ValueError('Read the full current target symbol; a narrow quote cannot establish absence of a boundary guard')
    return {**proof, 'evidence': evidence, 'consumer': consumer, 'binding_owner': 'harness',
            'qualification': 'source_bound_structural_evidence_not_semantic_proof'}


def probe_metadata(action):
    """Record optional descriptions without imposing variable/phase syntax."""
    values = {}
    for field in ['ordinary_input_desc', 'mutated_input_desc']:
        value = action.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(field + ' must be a string when supplied')
            values[field] = value[:1200]
    values['metadata_sha256'] = hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
    return values


def probe_use_qualification(code, check, consumer_verified, *, guard_required=False, requires_html_consumer=True):
    """Qualify probe evidence after execution; never prevent execution itself."""
    reasons = []
    if not unseeded_gate.completed_check(check):
        reasons.append('probe_did_not_complete_and_reach_current_target')
    if requires_html_consumer and not consumer_verified:
        reasons.append('producer_only_no_runtime_caller_or_static_consumer_review')
    return {'can_authorize_scanner_negative_edit': not reasons,
            'reasons': reasons,
            'rule': 'completed_target_and_boundary_specific_consumer',
            'requires_html_consumer':requires_html_consumer,
            'qualification_scope':'execution_evidence_for_supported_repair; not_a_security_label',
            'dynamic_execution_can_refute': False}


def register_preloaded_reads(editor, initial, reads):
    """Attest exact full-source ranges that were delivered in the initial input."""
    registered = []
    for row in initial.get('preloaded_source_ranges', []):
        path = row.get('path')
        source = editor.text(path)
        digest = citations.source_hash(source)
        lo, hi = row.get('start_line'), row.get('end_line')
        if not isinstance(lo, int) or not isinstance(hi, int) or lo < 1 or hi < lo:
            raise ValueError('Invalid preloaded source range')
        quote = '\n'.join(source.splitlines()[lo - 1:hi])
        if row.get('source_sha256') != digest or row.get('source') != quote:
            raise ValueError('Preloaded source range does not match current candidate: ' + str(path))
        reads.setdefault(path, []).append((digest, lo, hi))
        editor.read_paths.add(path)
        registered.append({'path': path, 'start_line': lo, 'end_line': hi,
                           'source_sha256': digest, 'symbol': row.get('symbol'),
                           'relationship': row.get('relationship')})
    return registered


SYSTEM = '''You are auditing a functionally working Python implementation. Preserve ordinary behavior and repair supported security defects. Stock SAST warnings, change history and developer rationale are evidence to test, never labels. Do not seek hidden tests, reference patches, CVEs or benchmark answers.
Inspect the current target and its real callers/consumers. Form a concrete hypothesis, then assess it. Dynamic probes are diagnostic only: regardless of whether they pass, fail or raise, they can NEVER refute a hypothesis. A refutation must cite a current static rejecting guard, returned neutralization, or sanitizing/normalizing transformation and explain why it covers the forbidden representation. os.path.join does not normalize away .. segments. A clearly missing invariant can support a defect without a working exploit when the full target and relevant contract boundary are inspected, under the static rules below.
Normal executable Python probes are allowed after an inconclusive assessment and after editing. Variable names and tracer_phase calls are optional. Use the supplied tracer_observe(name, value) or stdout for observations; no fixed observation keys are required. Optional ordinary_input_desc and mutated_input_desc may describe inputs. A completed source-matched target-reaching probe can support repair of public input validators, authentication, SQL/URL/AST filtering and state-creation contracts without an external caller. It is execution evidence, not proof the property holds: explain the actual observed violation before assessing supported. For an HTML/label output producer only, also cover a real caller/renderer frame or supply static consumer_review showing downstream escaping does not enforce the property. A raw producer string alone cannot authorize its edit. A failed or non-reaching probe stays inconclusive. Rerun the same program after a dynamic-supported edit and validate functionality; the official security test determines SecPass later.
For static_invariant with enforcement_kind=missing_boundary_guard, consumer may be null for an intrinsic input contract or where no in-file callers remain uninspected. Preloaded callers count as inspected; no duplicate consumer object or read is required for these cases. HTML output producers require explicit consumer evidence through rendering/escaping. Source-bound static proof remains mandatory for any refutation.
The complete top selected target functions and immediate in-file callers supplied at turn 0 are already registered as current reads. Do not re-read them solely to satisfy citation bookkeeping. Read anything else before citing or editing it. If you support a vulnerability, apply a minimal repair, reassess the current code, and run functional validation before finishing. The harness blocks diagnosis-only finish while a supported target has no retained repair and warns with six turns remaining.
C0 receives the shared snapshot and SAST context. C1 adds temporal/GumTree cards, C2 adds recorded reasoning cards, and C3 adds both and their links. C1/C2/C3 also receive deterministic AST invariant-completeness cues derived from their enabled evidence and current syntax; treat them as review questions, not vulnerability labels. Reply as JSON {"actions":[...]} with 1..3 actions. Available tools are read, search, structure, flow, codeql, rationale (C2/C3), hypothesis, assess, check, edit, syntax, functional, decision(s), finish. Keep unsupported findings unresolved. Hidden security evaluation occurs only after finalization and never supplies investigator feedback.'''
