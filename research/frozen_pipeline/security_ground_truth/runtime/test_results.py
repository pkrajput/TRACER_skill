"""Conservative terminal-result parsing; raw execution artifacts stay unchanged."""
import re

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def parse_test_log(stdout, stderr, exit_code, execution_status):
    text = ANSI.sub('', stdout + '\n' + stderr)
    result = {'parser_version': 'terminal_results_v3', 'recognized': False,
              'framework': None, 'counts': {}, 'failure_nodes': [], 'error_nodes': [],
              'exit_code': exit_code, 'pass': None}
    # GNU make uses exit 2 when a recipe exits 1. Require that exact wrapper
    # evidence plus a valid terminal test summary; never reinterpret a generic
    # exit 2, pytest collection error, signal, or timeout as completed tests.
    wrapper_failure = exit_code == 2 and bool(re.search(r'^make(?:\[\d+\])?: \*\*\* \[[^\n]+\] Error 1\s*$', text, re.MULTILINE))
    allowed_status = execution_status in {'executed', 'unrecognized_or_empty_test_output'} or (
        wrapper_failure and execution_status == 'nonstandard_exit_requires_review')
    effective_exit = 1 if wrapper_failure else exit_code
    if effective_exit not in (0, 1) or not allowed_status:
        return result
    if wrapper_failure:
        result.update(effective_test_exit_code=1, wrapper_evidence='make_recipe_error_1_with_terminal_test_summary')
    # A final pytest summary is required; per-test progress and arbitrary text
    # containing "passed" cannot establish completion.
    summaries = [line.strip().strip('=').strip() for line in text.splitlines()
                 if re.fullmatch(r'=*\s*(?:\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?)(?:, )?)+ in .+?\s*=*', line.strip())]
    if summaries:
        final = summaries[-1]
        counts = {name.rstrip('s'): int(count) for count, name in re.findall(r'(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?)', final)}
        total = sum(counts.get(name, 0) for name in ('passed', 'failed', 'error', 'skipped', 'xfailed', 'xpassed'))
        if total == 0 or (counts.get('passed', 0) == 0 and counts.get('failed', 0) == 0):
            return result
        result.update(framework='pytest', counts=counts,
                      failure_nodes=[node.split(' - ', 1)[0] for node in re.findall(r'^FAILED\s+([^\n]+)', text, re.MULTILINE)],
                      error_nodes=[node.split(' - ', 1)[0] for node in re.findall(r'^ERROR\s+([^\n]+)', text, re.MULTILINE)])
    else:
        matches = list(re.finditer(r'^Ran (\d+) tests? in [^\n]+\n\s*\n(OK(?: \([^\n]+\))?|FAILED \([^\n]+\))\s*$', text, re.MULTILINE))
        if not matches or int(matches[-1].group(1)) == 0:
            return result
        match = matches[-1]
        counts = {'total': int(match.group(1)), 'failed': 0, 'error': 0, 'skipped': 0}
        for key, value in re.findall(r'(?:\(|,\s*)(failures|errors|skipped)=(\d+)', match.group(2)):
            counts[{'failures': 'failed', 'errors': 'error', 'skipped': 'skipped'}[key]] = int(value)
        expected=re.search(r'expected failures=(\d+)',match.group(2))
        counts['expected_failures']=int(expected.group(1)) if expected else 0
        counts['passed'] = counts['total'] - counts['failed'] - counts['error'] - counts['skipped'] - counts['expected_failures']
        if counts['passed'] <= 0 and counts['failed'] == 0:
            return result
        result.update(framework='unittest', counts=counts,
                      failure_nodes=re.findall(r'^FAIL: (\S+) \(([^\n]+)\)', text, re.MULTILINE),
                      error_nodes=re.findall(r'^ERROR: (\S+) \(([^\n]+)\)', text, re.MULTILINE))
        result['failure_nodes'] = [scope+'::'+name for name, scope in result['failure_nodes']]
        result['error_nodes'] = [scope+'::'+name for name, scope in result['error_nodes']]
    failed = result['counts'].get('failed', 0)
    errors = result['counts'].get('error', 0)
    # Contradictory exit/summary evidence remains unknown.
    if (effective_exit == 0 and (failed or errors)) or (effective_exit == 1 and not (failed or errors)):
        result['contradictory_exit_summary'] = True
        return result
    result['recognized'] = True
    result['pass'] = exit_code == 0 and failed == errors == 0 and result['counts'].get('passed', 0) > 0
    return result
