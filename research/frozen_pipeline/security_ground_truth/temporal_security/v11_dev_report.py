"""Offline matched v6-through-v11 development report; never model input."""
from __future__ import annotations

import collections
import json
import math
from pathlib import Path
import re
import sqlite3

from security_ground_truth.runtime.common import sha256, utcnow, write_json
from security_ground_truth.repair_check.official_score import load_authors_classes
from .dev_pilot_report import read, score_cell, localization
from .v8_dev_report import measured, outcome
from .v10_protocol import negative_probe_reason
from .v11_integrity import execution_code_audit


WAGTAIL = 'd7d694dafa51f88ef9c1b5f3'
CURRENT = 'v11-dev'


def report_status(runner_status, current_phases, verification_status):
    complete = runner_status == 'completed' and current_phases == 40
    if verification_status:
        return ('passed' if verification_status == 'passed' and complete else 'failed'), complete
    if complete:
        return 'awaiting_final_verification', complete
    return runner_status or 'incomplete', complete


def detail(cell):
    m = measured(cell)
    result = read(cell / 'result.json', {})
    trace = read(cell / 'trajectory.json', [])
    actions = []
    refutations = []
    undefined = []
    coverage = []
    check_rejections = 0
    accepted_edits = 0
    malformed_action_batches = 0
    primary_read_errors = collections.Counter()
    for turn in trace:
        answer = turn.get('answer', {}) if isinstance(turn, dict) else {}
        raw_actions = answer.get('actions') if isinstance(answer, dict) else None
        observations = turn.get('observations', []) if isinstance(turn, dict) else []
        observations = observations if isinstance(observations, list) else []
        if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= 3:
            malformed_action_batches += 1
            continue
        for raw_action, raw_observation in zip(raw_actions, observations):
            action = raw_action if isinstance(raw_action, dict) else {}
            observation = raw_observation if isinstance(raw_observation, dict) else {}
            actions.append((action, observation))
            accepted_edits += (action.get('action') == 'edit'
                               and observation.get('status') == 'edited')
            if observation.get('status') == 'blocked_read_binge':
                primary_read_errors[observation.get('error', '')] += 1
            if observation.get('status') in {'invalid_action', 'blocked_repeated_action'}:
                error = observation.get('error', '')
                check_rejections += action.get('action') == 'check'
                if action.get('action') == 'assess' and action.get('decision') == 'refuted':
                    refutations.append({
                        'action': action, 'error': error,
                        'explicit_negative_probe_reason': negative_probe_reason(
                            action.get('reason', ''))})
                if 'undefined Python names' in error:
                    undefined.append({'action': action, 'error': error})
            coverage.extend(observation.get('edited_branch_warnings', []))
    hypotheses = read(cell / 'hypotheses.json', {})
    routes = []
    for identifier, gate in result.get('unseeded_repair_gates', {}).items():
        routes.append({'hypothesis_id': identifier, 'mode': gate.get('mode', 'unknown'),
                       'retained_path': hypotheses.get(identifier, {}).get('path')
                       in result.get('changed_paths', []),
                       'dynamic_final_validated': identifier
                       in result.get('dynamically_validated_repair_hypothesis_ids', [])})
    m['unseeded_gate_rejections'] += sum(
        count for error, count in m['errors'].items()
        if error.startswith('Inspect the downstream rendering consumer'))
    if primary_read_errors:
        combined_errors = collections.Counter(m['errors'])
        combined_errors.update(primary_read_errors)
        m['errors'] = dict(combined_errors)
        m['rejected'] += sum(primary_read_errors.values())
    check_evidence = read(cell / 'check_evidence.json', [])
    assessments = read(cell / 'assessments.json', [])
    primary_read_blocks = sum(primary_read_errors.values())
    return {
        **m, 'action_observations': len(actions) + malformed_action_batches,
        'executed_action_observations': len(actions),
        'malformed_action_batches': malformed_action_batches,
        'rejection_rate': m['rejected'] / (len(actions) + malformed_action_batches)
        if actions or malformed_action_batches else None,
        'qualified_protocol_probes': sum(
            bool(check.get('v11_protocol') or check.get('v10_protocol'))
            and check.get('probe_use_qualification', {}).get(
                'can_authorize_scanner_negative_edit', False)
            for check in check_evidence),
        'missing_target_symbol_rejections': sum(
            count for error, count in m['errors'].items()
            if 'entire target symbol before claiming' in error),
        'current_invariant_read_rejections': sum(
            count for error, count in m['errors'].items()
            if error.startswith('Read the cited invariant/consumer range')),
        'primary_read_coaching_blocks': primary_read_blocks,
        'blocked_refutations': refutations,
        'blocked_refutation_count': len(refutations),
        'explicit_negative_probe_refutation_blocks': sum(
            row['explicit_negative_probe_reason'] for row in refutations),
        'undefined_name_blocks': undefined,
        'undefined_name_block_count': len(undefined),
        'coverage_warning_events': len(coverage),
        'final_coverage_warnings': result.get('edited_branch_warnings') or [],
        'read_discipline': result.get('read_discipline'),
        'repair_routes': routes, 'result_error': result.get('error'),
        'check_action_attempts': sum(action.get('action') == 'check'
                                     for action, _ in actions),
        'check_action_rejections': check_rejections,
        'accepted_edit_actions': accepted_edits,
        'static_supported_assessments': sum(
            assessment.get('decision') == 'supported' for assessment in assessments),
        'discarded_unvalidated_patch': result.get(
            'unvalidated_patch_retained_separately', False)}


def failure_excerpt(cell):
    text = '\n'.join(path.read_text(errors='replace') for path in [
        cell / 'evaluation/sec/artifacts/test.stdout',
        cell / 'evaluation/sec/artifacts/test.stderr'] if path.exists())
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    return [line[:600] for line in text.splitlines()
            if re.match(r'^FAILED |^FAIL: |^ERROR: |^E\s+(?:AssertionError|NameError|TypeError|ValueError)|^AssertionError:|^\s*self\.assert|^\s*>\s*', line)]


def _budget(root, manifest, config):
    scope = config['budget_scope']
    ledger = Path(manifest['ledger_root']) / 'budget.sqlite'
    with sqlite3.connect('file:' + str(ledger) + '?mode=ro', uri=True) as database:
        costs = database.execute(
            "SELECT micro_usd,details FROM requests "
            "WHERE json_extract(details,'$.budget_scope')=?", (scope['id'],)).fetchall()
        total = database.execute(
            'SELECT COALESCE(SUM(micro_usd),0) FROM requests').fetchone()[0]
    provider = []
    unknown = []
    for micro, raw in costs:
        value = (json.loads(raw).get('usage') or {}).get('cost')
        if isinstance(value, (float, int)) and math.isfinite(value) and value >= 0:
            provider.append(value)
        else:
            unknown.append(micro)
    return {
        'provider_reported_usd': sum(provider),
        'accounted_usd': sum(cost[0] for cost in costs) / 1e6,
        'unknown_billing_requests': len(unknown),
        'unknown_reservations_usd': sum(unknown) / 1e6,
        'requests': len(costs),
        'incremental_cap_usd': scope['cap_micro_usd'] / 1e6,
        'starting_accounted_usd': scope['initial_total_micro_usd'] / 1e6,
        'absolute_ceiling_usd': (scope['initial_total_micro_usd']
                                 + scope['cap_micro_usd']) / 1e6,
        'total_accounted_usd': total / 1e6,
        'within_cap': (sum(cost[0] for cost in costs) <= scope['cap_micro_usd']
                       and total <= scope['initial_total_micro_usd']
                       + scope['cap_micro_usd'])}


def report(root):
    root = Path(root)
    manifest = read(root / 'manifest.json')
    try:
        executing_code = execution_code_audit(manifest, __file__)
    except Exception as exc:
        executing_code = {
            'execution_repo': str(Path(__file__).resolve().parents[2]),
            'files': 0, 'expected_files': 0, 'changed': [],
            'matched': False, 'error': str(exc),
        }
    cases = read(root / 'cases.json')
    config = read(root / 'config.json')
    bases = collections.OrderedDict([
        ('v6', Path(manifest['parent']) / 'experiment'),
        ('v7-dev', root.parent / 'temporal_security_v7_dev'),
        ('v8-dev', root.parent / 'temporal_security_v8_dev'),
        ('v9-dev', root.parent / 'temporal_security_v9_dev'),
        ('v10-dev', root.parent / 'temporal_security_v10_dev'),
        (CURRENT, root)])
    namespace = load_authors_classes(root / 'upstream_logs.py')
    rows = []
    case_names = {case['case_key']: case['instance_id'].rsplit('_', 1)[0]
                  for case in cases}
    for case in cases:
        for version, base in bases.items():
            for arm in ['C0', 'C3']:
                cell = base / 'cells' / case['case_key'] / arm
                rows.append({
                    'case_key': case['case_key'], 'instance_id': case['instance_id'],
                    'generator': case['model_name'], 'version': version, 'arm': arm,
                    'cell': str(cell), 'metrics': detail(cell),
                    'evaluation': score_cell(cell, case, namespace,
                                             allow_archived_noop=version == 'v6'),
                    'localization': localization(cell, case),
                    'security_failure_excerpt': failure_excerpt(cell)})
    summary = {}
    total_fields = [
        'rejected', 'action_observations', 'executed_action_observations',
        'malformed_action_batches', 'citation_rejections',
        'unseeded_gate_rejections', 'blocked_refutation_count',
        'explicit_negative_probe_refutation_blocks', 'undefined_name_block_count',
        'check_action_attempts', 'check_action_rejections', 'accepted_edit_actions',
        'qualified_protocol_probes', 'missing_target_symbol_rejections',
        'current_invariant_read_rejections', 'primary_read_coaching_blocks']
    for version in bases:
        for arm in ['C0', 'C3']:
            selected = [row for row in rows
                        if row['version'] == version and row['arm'] == arm]
            complete = [row for row in selected if outcome(row) != 'incomplete']
            totals = {key: sum(row['metrics'][key] for row in selected)
                      for key in total_fields}
            errors = collections.Counter()
            probes = collections.Counter()
            for row in selected:
                errors.update(row['metrics']['errors'])
                probes.update(row['metrics']['probes'])
            summary[version + ':' + arm] = {
                'cells': len(selected), 'completed_evaluations': len(complete),
                'terminal_phases': sum(
                    sum(row['evaluation']['terminal_completed'].values())
                    for row in selected if row['evaluation']),
                'func_pass': sum(
                    bool(row['evaluation'])
                    and row['evaluation']['terminal_completed']['func']
                    and row['evaluation']['score']['func_pass'] for row in selected),
                'sec_pass': sum(row['evaluation']['score']['sec_pass'] for row in complete),
                'actionable9_sec_pass': sum(
                    row['case_key'] != WAGTAIL
                    and row['evaluation']['score']['sec_pass'] for row in complete),
                'turn_limits': sum(row['metrics']['status'] == 'turn_limit'
                                   for row in selected),
                'repair_errors': sum(row['metrics']['status'] == 'repair_error'
                                     for row in selected),
                'actionable_edited_cells': sum(
                    row['case_key'] != WAGTAIL
                    and row['metrics']['accepted_edit_actions'] > 0 for row in selected),
                'retained_patch_cells': sum(row['metrics']['edited'] for row in selected),
                'supported_but_no_edit_cells': sum(
                    row['metrics']['static_supported_assessments'] > 0
                    and not row['metrics']['accepted_edit_actions'] for row in selected),
                'errors': dict(errors), 'probes': dict(probes),
                'final_coverage_warning_cells': sum(
                    bool(row['metrics']['final_coverage_warnings']) for row in selected)
                if version in {'v9-dev', 'v10-dev', 'v11-dev'} else None,
                'rejected_per_cell': totals['rejected'] / len(selected),
                'rejection_rate': totals['rejected'] / totals['action_observations']
                if totals['action_observations'] else None,
                **totals}

    budget = _budget(root, manifest, config)
    review = read(root / 'report/MECHANISM_REVIEW.json', {})
    findings = read(root / 'report/DIAGNOSTIC_FINDINGS.json', {})
    final_verification = read(root / 'report/V11_FINAL_VERIFICATION.json', {})
    runner_status = read(root / 'status.json', {}).get('status')
    current_phases = sum(summary[CURRENT + ':' + arm]['terminal_phases']
                         for arm in ['C0', 'C3'])
    verification_status = final_verification.get('status')
    status, fresh_evaluations_complete = report_status(
        runner_status, current_phases, verification_status)
    if not executing_code['matched']:
        status = 'failed'
    data = {
        'utc': utcnow(), 'status': status, 'runner_status': runner_status,
        'final_verification_status': verification_status,
        'fresh_evaluations_complete': fresh_evaluations_complete,
        'summary': summary, 'rows': rows, 'budget': budget,
        'case_keys': [case['case_key'] for case in cases],
        'failed_edit_case_keys': [case['case_key'] for case in cases
                                  if not case['official_baseline_score']['sec_pass']],
        'mechanism_review': review, 'diagnostic_findings': findings,
        'execution_code_audit': executing_code,
        'protected_overlap': 0, 'full_cohort_dispatched': False,
        'reporter_sha256': sha256(Path(__file__)),
        'mechanism_review_sha256': sha256(root / 'report/MECHANISM_REVIEW.json')
        if review else None, 'final_verification': final_verification}
    write_json(root / 'report/V11_DEV_COMPARISON.json', data)

    verification_label = verification_status or 'pending'
    lines = [
        '# v11 matched development diagnostic: 10 cases, C0/C3', '',
        f"Status: **{data['status']}** (runner: **{runner_status}**; final verification: "
        f"**{verification_label}**). 20 selected cells; {current_phases}/40 fresh official "
        'phases have recognized terminal completion. Same original candidates and 22-turn '
        'limit. Protected 142 attempts / 48 tasks excluded; no bulk release.', '',
        ('Executing report code matches the prepared frozen implementation.'
         if executing_code['matched'] else
         'Executing report code differs from the prepared frozen implementation; this '
         'report is failed.'), '',
        'C0 receives the clean current snapshot, SAST context, preloaded targets and shared '
        'runtime gates. C3 adds temporal history, recorded rationale, linked divergence and '
        'deterministic AST completeness cues. v11 also repairs refutation handling, coaches '
        'early primary-target assessment, relaxes qualified post-edit probe matching, and '
        'uses the longer provider timeout. Cross-version results are engineering diagnostics '
        'on a selected development cohort.', '',
        f"Original candidates: FuncPass {sum(c['official_baseline_score']['func_pass'] for c in cases)}/10; "
        f"SecPass {sum(c['official_baseline_score']['sec_pass'] for c in cases)}/10.", '',
        '| Revision / arm | Terminal phases | FuncPass | SecPass | Actionable 9 SecPass | '
        'Rejected / action events | Malformed batches | Rejected/cell | Turn limit |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, values in summary.items():
        rate = (f"{values['rejection_rate']:.2%}"
                if values['rejection_rate'] is not None else 'n/a')
        lines.append(
            f"| {name} | {values['terminal_phases']}/20 | {values['func_pass']}/10 | "
            f"{values['sec_pass']}/10 | {values['actionable9_sec_pass']}/9 | "
            f"{values['rejected']}/{values['action_observations']} ({rate}) | "
            f"{values['malformed_action_batches']} | {values['rejected_per_cell']:.2f} | "
            f"{values['turn_limits']}/10 |")
    if findings:
        lines += ['', '## Diagnostic conclusion', '', findings.get('conclusion', ''), '']
        lines.extend('- ' + item for item in findings.get('findings', []))
    evaluation_claim = (
        'Every v11 candidate, including a no-op, received a fresh functional and security '
        'evaluation.' if fresh_evaluations_complete else
        'The 40-phase fresh-evaluation requirement is incomplete; current pass counts are '
        'diagnostic only and must not be treated as a final v11 result.')
    lines += [
        '', 'Pass counts require recognized terminal execution and use the benchmark’s '
        'official expected-failure allowances. ' + evaluation_claim, '',
        f"Provider-reported spend **${budget['provider_reported_usd']:.6f}**; accounted "
        f"**${budget['accounted_usd']:.6f} / ${budget['incremental_cap_usd']:.2f}**; "
        f"{budget['requests']} requests; {budget['unknown_billing_requests']} unknown-billing "
        f"reservations. Starting ledger **${budget['starting_accounted_usd']:.6f}**; total "
        f"**${budget['total_accounted_usd']:.6f}**; ceiling "
        f"**${budget['absolute_ceiling_usd']:.6f}**.", '',
        '## Wagtail preservation', '', '| Revision / arm | Outcome |', '|---|---|']
    for row in rows:
        if row['case_key'] == WAGTAIL:
            lines.append(f"| {row['version']} / {row['arm']} | {outcome(row)} |")

    versions = list(bases)
    columns = [(version, arm) for arm in ['C0', 'C3'] for version in versions]
    lines += ['', '## Matched outcomes for every selected case', '',
              '| Case | ' + ' | '.join(version + ' ' + arm for version, arm in columns) + ' |',
              '|---|' + '|'.join('---' for _ in columns) + '|']
    for case in cases:
        matching = {(row['version'], row['arm']): row for row in rows
                    if row['case_key'] == case['case_key']}
        values = ' | '.join(outcome(matching[column]) for column in columns)
        lines.append('| ' + case_names[case['case_key']] + ' / ' + case['case_key']
                     + ' | ' + values + ' |')

    lines += ['', '## Guardrails and execution friction', '',
              '| Revision / arm | Refutations blocked | Invariant-read rejections | '
              'Primary-read coaching blocks | Qualified probes | Undefined-name blocks | '
              'Coverage-warning cells | Repair errors |',
              '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name, values in summary.items():
        coverage = (values['final_coverage_warning_cells']
                    if values['final_coverage_warning_cells'] is not None else 'not recorded')
        lines.append(
            f"| {name} | {values['blocked_refutation_count']} | "
            f"{values['current_invariant_read_rejections']} | "
            f"{values['primary_read_coaching_blocks']} | "
            f"{values['qualified_protocol_probes']} | "
            f"{values['undefined_name_block_count']} | {coverage} | "
            f"{values['repair_errors']} |")
    lines += ['', 'Refutation blocks and coaching blocks count rejected actions, not '
              'independently adjudicated security claims. Probe qualification is execution '
              'evidence and is distinct from an official security pass. A malformed action '
              'batch is one response-level rejection and represents zero executed actions.', '']
    for arm in ['C0', 'C3']:
        lines += [f'### v11 {arm}: rejected action reasons', '']
        for error, count in sorted(summary[CURRENT + ':' + arm]['errors'].items(),
                                   key=lambda item: (-item[1], item[0])):
            lines.append(f'- {count}: {error}')

    lines += ['', '## v11 per-case mechanism and outcome', '',
              '| Case / arm | Localized invariant | Refutation / repair route | '
              'Official outcome / remaining failure |',
              '|---|---|---|---|']
    current_rows = [row for row in rows if row['version'] == CURRENT]
    for row in current_rows:
        note = review.get(row['case_key'], {}).get(row['arm'], {})
        if isinstance(note, str):
            note = {'mechanism': note}
        route = ', '.join(
            f"{gate['mode']} ({'retained' if gate['retained_path'] else 'discarded'})"
            for gate in row['metrics']['repair_routes']) or 'no recorded scanner-negative route'
        conclusion = (note.get('remaining_failure')
                      or '; '.join(row['security_failure_excerpt'][:2])
                      or 'No assertion excerpt extracted; inspect raw logs.')
        cells = [
            case_names[row['case_key']] + ' / ' + row['case_key'] + ' / ' + row['arm'],
            note.get('localized_invariant', 'pending semantic review'),
            note.get('route', route) + '; ' + note.get(
                'self_refutation', 'refutation blocks: '
                + str(row['metrics']['blocked_refutation_count'])),
            outcome(row) + '; ' + conclusion]
        lines.append('| ' + ' | '.join(
            str(value).replace('|', '\\|').replace('\n', ' ') for value in cells) + ' |')
    for row in current_rows:
        lines += ['', f"## {row['case_key']} / {row['arm']}", '']
        note = review.get(row['case_key'], {}).get(row['arm'], {})
        if note:
            lines.append(note if isinstance(note, str) else note.get('mechanism', ''))
        for hypothesis in row['localization']['hypotheses']:
            lines.append('- ' + str(hypothesis['hypothesis_id']) + ' `'
                         + str(hypothesis['path']) + '`: ' + str(hypothesis['mechanism'])
                         + ' Property: ' + str(hypothesis['security_property']))
        lines += ['', 'Retained locations: ' +
                  (', '.join(path + '::' + symbol
                             for path, symbol in row['localization']['changed_symbols'])
                   or 'none') + '.']
        if isinstance(note, dict) and note.get('remaining_failure'):
            lines += ['', 'Evaluator-selected official failure / outcome: '
                      + note['remaining_failure']]
        elif row['security_failure_excerpt']:
            lines += ['', 'Official security failure excerpts:', '', '```text',
                      *row['security_failure_excerpt'][:16], '```']
        lines += ['', 'Evidence directory: `' + row['cell'] + '`.']
    lines += ['', 'Full hypotheses, rejected actions, gate evidence, patches and official '
              'logs are linked by absolute cell paths in the JSON report. Hidden evaluation '
              'was never returned to the investigator. No candidate was rerolled from '
              'security results.']
    if final_verification:
        lines += ['', f"Final verification: **{final_verification['status']}**; "
                  f"{final_verification['actual_cells']} cells, "
                  f"{final_verification['official_phases_with_recognized_completion']} "
                  f"terminal-complete phases, {final_verification['protected_overlap']} "
                  f"protected overlap. Runner alive: {final_verification['runner_alive']}."]
    (root / 'report').mkdir(parents=True, exist_ok=True)
    (root / 'report/V11_DEV_COMPARISON.md').write_text('\n'.join(lines) + '\n')
    return data


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    report(parser.parse_args().root)
