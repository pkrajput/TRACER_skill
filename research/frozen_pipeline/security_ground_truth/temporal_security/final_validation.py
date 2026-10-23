"""One evaluator-only public validation opportunity at bounded finalization."""


def current_verdict(records, patch_sha256):
    for record in reversed(records):
        score = record.get('functional_result', {})
        if (record.get('candidate_patch_sha256') == patch_sha256
                and record.get('status') == 'executed'
                and score.get('test_status') == 'completed'
                and score.get('terminal_result', {}).get('recognized') is True
                and type(score.get('pass')) is bool):
            return score['pass']
    return None


def finalize(*, enabled, status, patch, patch_sha256, records, run_public):
    """Never rerun a known current failure or invoke the hidden evaluator.

    Other repair gates remain enforced by the caller. Final validation is not a
    substitute for a required source assessment or post-edit security check.
    """
    if not enabled or not patch or status not in {'turn_limit', 'finished'}:
        return {'status': 'not_applicable', 'executions': 0}
    prior = current_verdict(records, patch_sha256)
    if prior is not None:
        return {'status': 'reuse_current_verdict', 'executions': 0, 'pass': prior}
    try:
        result = run_public()
    except Exception as exc:
        result = {'status': 'tool_execution_error', 'error_type': type(exc).__name__,
                  'error': str(exc)[:1000], 'candidate_patch_sha256': patch_sha256}
    result = {**result, 'finalization_execution': True,
              'reason': 'current_nonempty_candidate_lacks_terminal_public_validation'}
    records.append(result)
    verdict = current_verdict([result], patch_sha256)
    return {'status': 'executed', 'executions': 1, 'pass': verdict,
            'candidate_patch_sha256': patch_sha256, 'hidden_security_used': False}
