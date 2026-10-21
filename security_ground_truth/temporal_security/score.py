"""Report matched official benchmark outcomes, never model-generated judgments."""
from __future__ import annotations

import collections
import json
from pathlib import Path
import random

from security_ground_truth.runtime.common import utcnow, write_json

ARMS = ('C0', 'C1', 'C2', 'C3')


def benchmark_score(evaluation):
    """Accept the evaluator's score only; repair/check claims are not labels."""
    if not isinstance(evaluation, dict):
        return None
    score = evaluation.get('score')
    if not isinstance(score, dict) or any(type(score.get(k)) is not bool for k in ['func_pass', 'sec_pass']):
        return None
    if score['sec_pass'] and not score['func_pass']:
        raise ValueError('Official SecPass requires FuncPass')
    return score


def infrastructure_incomplete(score):
    if score is None:
        return True
    return any(run.get('test_status') in {'indeterminate', 'startup_error', 'timeout'}
               for run in score.get('runs', {}).values())


def summarize(rows, cohort_size):
    scored = [r for r in rows if r['after'] is not None]
    # An evaluator timeout is an operational nonpass, not evidence of insecurity.
    known_before = [r for r in scored if not infrastructure_incomplete(r['before'])]
    insecure = [r for r in known_before if r['before']['func_pass'] and not r['before']['sec_pass']]
    secure = [r for r in known_before if r['before']['sec_pass']]
    return {
        'cohort_size': cohort_size, 'completed_cells': len(rows), 'scored_cells': len(scored),
        'missing_cells': cohort_size - len(rows),
        'unscored_completed_cells': len(rows) - len(scored),
        'infrastructure_incomplete': sum(r['infrastructure_incomplete'] for r in rows),
        'baseline_infrastructure_incomplete_on_scored': len(scored) - len(known_before),
        'baseline_unknown_to_secpass': sum(r['after']['sec_pass'] for r in scored
                                         if infrastructure_incomplete(r['before'])),
        'func_before_on_scored': sum(r['before']['func_pass'] for r in scored),
        'func_after_on_scored': sum(r['after']['func_pass'] for r in scored),
        'sec_before_on_scored': sum(r['before']['sec_pass'] for r in scored),
        'sec_after_on_scored': sum(r['after']['sec_pass'] for r in scored),
        'func_pass_rate_before_on_scored': sum(r['before']['func_pass'] for r in scored) / len(scored) if scored else None,
        'func_pass_rate_after_on_scored': sum(r['after']['func_pass'] for r in scored) / len(scored) if scored else None,
        'sec_pass_rate_before_on_scored': sum(r['before']['sec_pass'] for r in scored) / len(scored) if scored else None,
        'sec_pass_rate_after_on_scored': sum(r['after']['sec_pass'] for r in scored) / len(scored) if scored else None,
        'insecure_before_on_scored': len(insecure),
        'insecure_converted_to_secpass': sum(r['after']['sec_pass'] for r in insecure),
        'insecure_conversion_rate': sum(r['after']['sec_pass'] for r in insecure) / len(insecure) if insecure else None,
        'secure_before_on_scored': len(secure),
        'security_regressions': sum(not r['after']['sec_pass'] for r in secure),
        'security_regressions_with_completed_execution': sum(not r['after']['sec_pass'] and not r['infrastructure_incomplete'] for r in secure),
        'functional_regressions': sum(r['before']['func_pass'] and not r['after']['func_pass'] for r in scored),
        'functional_regressions_with_completed_execution': sum(r['before']['func_pass'] and not r['after']['func_pass']
                                                               and not r['infrastructure_incomplete'] for r in scored),
        'changed_patches': sum(r['patch_changed'] for r in rows),
        'repair_errors': sum(r['repair_status'] in {'repair_error', 'error', 'failed'} for r in rows),
        'all_outcomes_available': len(scored) == cohort_size,
        'all_executions_complete': len(scored) == cohort_size and not any(
            r['infrastructure_incomplete'] or infrastructure_incomplete(r['before']) for r in rows),
    }


def cluster_bootstrap(rows, seed=1701, replicates=1000, *, baseline_arm='C0', treatment_arm='C3'):
    if baseline_arm not in ARMS or treatment_arm not in ARMS or baseline_arm == treatment_arm:
        raise ValueError('A contrast needs two different valid arms')
    contrast_arms = {baseline_arm, treatment_arm}
    by_case = collections.defaultdict(dict)
    for row in rows:
        if row['arm'] in contrast_arms:
            by_case[row['case_key']][row['arm']] = row
    clusters = collections.defaultdict(list)
    for pair in by_case.values():
        if set(pair) != contrast_arms or any(r['after'] is None or r['infrastructure_incomplete'] for r in pair.values()):
            continue
        base, history = pair[baseline_arm], pair[treatment_arm]
        clusters[base['instance_id']].append(int(history['after']['sec_pass']) - int(base['after']['sec_pass']))
    all_values = [v for group in clusters.values() for v in group]
    info = {'contrast': f'{treatment_arm} minus {baseline_arm} SecPass on paired cases with completed evaluation execution',
            'baseline_arm': baseline_arm, 'treatment_arm': treatment_arm,
            'cluster_unit': 'instance_id; all generator attempts for a sampled task travel together',
            'clusters': len(clusters), 'paired_attempts': sum(map(len, clusters.values())),
            'difference': sum(all_values) / len(all_values) if all_values else None,
            'treatment_only_secpass': all_values.count(1),
            'baseline_only_secpass': all_values.count(-1),
            'tied_outcomes': all_values.count(0),
            'seed': seed, 'replicates': replicates}
    if len(clusters) < 10:
        return {**info, 'status': 'insufficient_clusters_minimum_10'}
    grouped = list(clusters.values())
    rng = random.Random(seed)
    samples = []
    for _ in range(replicates):
        values = [v for _ in grouped for v in rng.choice(grouped)]
        samples.append(sum(values) / len(values))
    samples.sort()
    return {**info, 'status': 'computed', 'difference': sum(all_values) / len(all_values),
            'percentile_95_ci': [samples[int(.025 * (replicates - 1))], samples[int(.975 * (replicates - 1))]],
            'note': 'Descriptive paired cluster bootstrap; excludes infrastructure-incomplete pairs, whose count is reported separately.'}


def preparation_dispositions(root):
    cohort_path = root / 'cohort.json'
    if not cohort_path.exists():
        return {'status': 'cohort_manifest_unavailable'}
    cohort = json.loads(cohort_path.read_text())
    eligible = [r for r in cohort['records'] if r['published_result']['func_pass_member']]
    results_path = root / 'prep/results.json'
    results = json.loads(results_path.read_text()) if results_path.exists() else []
    by_record = {r['record_id']: r for r in results}
    dispositions = []
    for row in eligible:
        result = by_record.get(row['record_id'])
        dispositions.append({'record_id': row['record_id'], 'model': row['model_name'],
            'instance_id': row['instance_id'], 'status': result['status'] if result else 'pending_preparation',
            'published_func_pass': True, 'published_sec_pass': row['published_result']['sec_pass_member'],
            'local_baseline_score': result.get('official_baseline_score') if result else None,
            'error': result.get('error') if result else None})
    prep_status = root / 'prep/status.json'
    return {'status': json.loads(prep_status.read_text()).get('status') if prep_status.exists() else 'unknown',
            'all_archived_attempts': cohort['denominator'], 'published_functional_candidates': len(eligible),
            'statuses': dict(collections.Counter(r['status'] for r in dispositions)),
            'all_candidate_dispositions': dispositions,
            'nonfunctional_published_attempts_outside_repair': cohort['denominator'] - len(eligible)}


def write_report(root, cases, completed, *, preparation_root=None):
    """Write RESULTS.json / REPORT.md from cases and completed evaluator records.

    cases: iterable of preparation records with official_baseline_score.
    completed: {case_key, arm, repair, evaluation}, one final candidate per cell.
    Missing results stay missing; partial comparisons use matched scored rows.
    """
    root = Path(root)
    lookup = {c['case_key']: c for c in cases}
    if len(lookup) != len(cases):
        raise ValueError('Duplicate registered cases')
    if any(c['official_baseline_score']['func_pass'] is not True for c in cases):
        raise ValueError('Repair report cohort requires locally functional original outputs')
    rows = []; seen = set()
    for record in completed:
        key, arm = record['case_key'], record['arm']
        if key not in lookup or arm not in ARMS or (key, arm) in seen:
            raise ValueError('Unknown or duplicate case-arm evaluation')
        seen.add((key, arm))
        case = lookup[key]
        score = benchmark_score(record.get('evaluation'))
        repair = record.get('repair') or {}
        rows.append({'case_key': key, 'arm': arm, 'generator': case['generator'],
                     'instance_id': case['instance_id'], 'before': case['official_baseline_score'], 'after': score,
                     'infrastructure_incomplete': infrastructure_incomplete(score),
                     'baseline_infrastructure_incomplete': infrastructure_incomplete(case['official_baseline_score']),
                     'repair_status': repair.get('status', 'unreported'),
                     'patch_changed': bool(repair.get('patch_bytes', 0) or repair.get('changed_files')),
                     'evaluation_path': record.get('evaluation_path')})
    paired_keys = {key for key in lookup if all((key, arm) in seen for arm in ARMS)}
    generators = sorted({c['generator'] for c in cases})
    metadata = {'updated_utc': utcnow(), 'metric_source': 'official SusVibes evaluator scores only',
        'registered_locally_functional_cases': len(cases), 'completed_cells': len(rows),
        'complete_four_arm_cases': len(paired_keys), 'preparation': preparation_dispositions(Path(preparation_root) if preparation_root else root),
        'by_arm': {arm: summarize([r for r in rows if r['arm'] == arm], len(cases)) for arm in ARMS},
        'paired_four_arm': {arm: summarize([r for r in rows if r['arm'] == arm and r['case_key'] in paired_keys], len(paired_keys)) for arm in ARMS},
        'by_generator': {generator: {arm: summarize([r for r in rows if r['generator'] == generator and r['arm'] == arm],
            sum(c['generator'] == generator for c in cases)) for arm in ARMS} for generator in generators},
        'paired_cluster_bootstrap': cluster_bootstrap(rows),
        'hypothesis_contrasts': {
            'H1_C3_minus_C0': cluster_bootstrap(rows),
            'H2_C1_minus_C0': cluster_bootstrap(rows, treatment_arm='C1'),
            'H2_C3_minus_C2': cluster_bootstrap(rows, baseline_arm='C2'),
            'H3_C2_minus_C0': cluster_bootstrap(rows, treatment_arm='C2'),
            'H3_C3_minus_C1': cluster_bootstrap(rows, baseline_arm='C1')},
        'rows': rows,
        'missing_evaluations_are_security_failures': False,
        'baseline_timeouts_are_verified_insecurity': False,
        'published_labels_mixed_with_local_after_scores': False}
    write_json(root / 'RESULTS.json', metadata)
    lines = ['# SusVibes temporal-security results', '',
             f"Registered locally functional cases: {len(cases)}. Completed cells: {len(rows)}/{len(cases) * 4}. Cases completed in all four arms: {len(paired_keys)}.",
             'Both before and after use official SusVibes evaluation on the same original output. SecPass requires functional and security passing. Missing cells remain pending; infrastructure failures are listed separately.', '',
             '| Arm | Scored / cohort | Func before → after | Sec before → after | Verified insecure → secure | Functional regressions | After / baseline incomplete |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for arm, count in metadata['by_arm'].items():
        n = count['scored_cells']
        lines.append(f"| {arm} | {n}/{len(cases)} | {count['func_before_on_scored']} → {count['func_after_on_scored']} | "
                     f"{count['sec_before_on_scored']} → {count['sec_after_on_scored']} | {count['insecure_converted_to_secpass']}/{count['insecure_before_on_scored']} | "
                     f"{count['functional_regressions']} | {count['infrastructure_incomplete']} / {count['baseline_infrastructure_incomplete_on_scored']} |")
    lines += ['', 'Counts in each row compare exactly the same scored cases before and after. The JSON includes a complete-four-arm comparison, per-generator counts, secure-output regressions, every preparation disposition, and a paired task-cluster bootstrap.']
    lines += ['', 'Pass rates retain the official operational nonpass for timed-out execution, with incompleteness reported explicitly. Insecure-to-secure conversions require a completed insecure baseline; unknown-baseline successes are counted separately. Missing evaluations are never fabricated as failures.']
    if metadata['preparation'].get('status') != 'completed':
        lines += ['', '**Preparation is still incomplete; the registered cohort is not final.**']
    bootstrap = metadata['paired_cluster_bootstrap']
    if bootstrap['status'] == 'computed':
        lo, hi = bootstrap['percentile_95_ci']
        lines += ['', f"C3−C0 SecPass difference on evaluable pairs: {100 * bootstrap['difference']:.2f} percentage points; task-cluster bootstrap 95% interval [{100 * lo:.2f}, {100 * hi:.2f}], {bootstrap['paired_attempts']} attempts / {bootstrap['clusters']} tasks."]
    else:
        lines += ['', 'C3−C0 confidence interval pending at least 10 completed task clusters.']
    lines += ['', '| Hypothesis contrast | Paired attempts | SecPass difference (pp) | Treatment-only / baseline-only passes |',
              '|---|---:|---:|---:|']
    for name, contrast in metadata['hypothesis_contrasts'].items():
        difference = contrast['difference']
        display = f'{100 * difference:.2f}' if difference is not None else 'pending'
        lines.append(f"| {name} | {contrast['paired_attempts']} | {display} | "
                     f"{contrast['treatment_only_secpass']} / {contrast['baseline_only_secpass']} |")
    path = root / 'REPORT.md'
    temporary = path.with_suffix('.md.tmp')
    temporary.write_text('\n'.join(lines) + '\n')
    temporary.replace(path)
    return metadata
