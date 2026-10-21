"""Compose SAST triage without converting model decisions into gold labels."""
from __future__ import annotations

from collections import Counter


def compose(alerts, decisions, seed_ids, *, labels=None, additions=None, validated_additions=None, source_manifest_sha256=None):
    """Return complete alert accounting and a scoped labeled decision matrix.

    labels is an evaluator-only mapping keyed by exact alert ID. Each row must
    name an independent source and a scope rationale. No task-level propagation.
    An FP prediction proposes suppression; it is not an independently verified FP.
    """
    ids = [a['alert_id'] for a in alerts]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate scanner alert IDs')
    seeds = set(seed_ids)
    if not seeds <= set(ids):
        raise ValueError('Seed outside baseline')
    by_id, conflicted = {}, set()
    for row in decisions:
        aid = row.get('alert_id')
        if aid not in seeds:
            continue
        verdict = row.get('decision', 'unresolved')
        if verdict not in {'tp', 'fp', 'unresolved'}:
            verdict = 'unresolved'
        if aid in by_id and by_id[aid] != verdict:
            conflicted.add(aid)
        if aid in conflicted:
            verdict = 'unresolved'
        by_id[aid] = verdict
    matrix = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
    operational_matrix = dict(matrix)
    abstentions, rows = Counter(), []
    for alert in alerts:
        aid = alert['alert_id']
        verdict = by_id.get(aid, 'unresolved') if aid in seeds else 'not_investigated'
        gold = (labels or {}).get(aid)
        if gold is not None and (gold.get('label') not in {'tp', 'fp'} or
                                 not gold.get('independent_source') or not gold.get('scope_rationale') or
                                 not source_manifest_sha256 or gold.get('source_manifest_sha256') != source_manifest_sha256):
            raise ValueError('Alert label requires independent source and exact scope rationale')
        category = None
        if gold and verdict in {'tp', 'fp'}:
            category = {('tp', 'tp'): 'TP', ('tp', 'fp'): 'FP',
                        ('fp', 'fp'): 'TN', ('fp', 'tp'): 'FN'}[(verdict, gold['label'])]
            matrix[category] += 1
        elif gold:
            abstentions[gold['label'] + ':' + verdict] += 1
        if gold:
            operational_prediction = 'fp' if verdict == 'fp' else 'tp'
            cell = {('tp', 'tp'): 'TP', ('tp', 'fp'): 'FP',
                    ('fp', 'fp'): 'TN', ('fp', 'tp'): 'FN'}[(operational_prediction, gold['label'])]
            operational_matrix[cell] += 1
        rows.append({'alert_id': aid, 'tool': alert['tool'], 'path': alert['path'],
                     'line': alert.get('line'), 'decision': verdict,
                     'action': 'proposed_suppression' if verdict == 'fp' else 'retain',
                     'independent_label': gold, 'matrix_cell': category})
    counts = Counter(r['action'] for r in rows)
    n = sum(matrix.values())
    # Additional findings require explicit property-level full-baseline matching,
    # not just absence of an alert on exactly the same line.
    # Investigator output can never certify itself, even if it emits fields
    # named "independent_validation". Only evaluator-supplied rows can qualify.
    added, pending = [], list(additions or [])
    for candidate in validated_additions or []:
        validated = candidate.get('independent_validation') or {}
        if (validated.get('confirmed') is True and validated.get('source') and
                source_manifest_sha256 and validated.get('source_manifest_sha256') == source_manifest_sha256 and
                candidate.get('baseline_property_match') == 'reviewed_absent' and candidate.get('property_id')):
            added.append(candidate)
        else:
            pending.append(candidate)
    unique_added = {c['property_id']: c for c in added}
    return {'schema': 'sast-triage-ledger-v1', 'baseline_alert_count': len(alerts),
            'selected_alert_count': len(seeds), 'retained_alert_count': counts['retain'],
            'proposed_suppression_count': counts['proposed_suppression'], 'alerts': rows,
            'confirmed_additions': list(unique_added.values()), 'unverified_additions': pending,
            'confusion_matrix_decided_labeled_alerts': matrix, 'labeled_abstentions': dict(abstentions),
            'confusion_matrix_retained_vs_suppressed_all_labeled': operational_matrix,
            'operational_matrix_note': 'Retained warnings count as positive alarms, including unresolved/uninvestigated; retention is not vulnerability confirmation',
            'labels_missing_count': len(alerts)-sum(operational_matrix.values()),
            'scoring_status': 'scoped_labels_available' if sum(operational_matrix.values()) else 'independent_alert_labels_required',
            'decided_labeled_count': n, 'accuracy_decided_labeled': (matrix['TP']+matrix['TN'])/n if n else None,
            'source_manifest_sha256': source_manifest_sha256,
            'matrix_scope': 'exact independently labeled scanner alerts only; excludes unresolved and uninvestigated, reported separately',
            'suppression_is_a_prediction_not_gold': True}
