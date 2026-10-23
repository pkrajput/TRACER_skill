"""Evaluator-only support for published test runners beyond pytest/unittest.

This parser never enters the investigator's tool environment. Original raw
artifacts and v12 model-facing validation remain immutable.
"""
import re
from security_ground_truth.runtime.test_results import parse_test_log,ANSI

PARSER_VERSION='official_terminal_extended_v2'


def parse_terminal(stdout,stderr,exit_code,status):
    original=parse_test_log(stdout,stderr,exit_code,status)
    text=ANSI.sub('',stdout+'\n'+stderr)
    if status not in ('executed','unrecognized_or_empty_test_output') or exit_code not in (0,1):return original
    # Some published runtests.py wrappers exit_on_failure(pytest.main(...))
    # before invoking flake8. The exact terminal pytest pass followed only by
    # the lint-phase marker and a missing flake8 executable proves test
    # completion, while the separate auxiliary failure remains recorded.
    # Do not generalize this to arbitrary contradictory exits or tracebacks.
    clean_out=ANSI.sub('',stdout).rstrip();marker='Running flake8 code linting'
    if (exit_code==1 and clean_out.endswith(marker) and 'in flake8_main' in stderr
            and re.search(r"FileNotFoundError:.*No such file or directory: ['\"]flake8['\"]",stderr)):
        tests=clean_out[:-len(marker)].rstrip()
        completed=parse_test_log(tests,'',0,'executed')
        if completed.get('recognized') and completed.get('framework')=='pytest' and completed.get('pass'):
            return {**completed,'parser_version':PARSER_VERSION,'exit_code':exit_code,
                'effective_test_exit_code':0,'post_test_auxiliary_failure':'missing_flake8_executable',
                'wrapper_evidence':'terminal_pytest_pass_then_missing_flake8_in_lint_phase'}
    framework=None;counts=None
    trial=list(re.finditer(r'^Ran (\d+) tests? in [^\n]+\n\s*\n(PASSED|FAILED)(?: \(([^\n]*)\))?\s*$',text,re.M))
    if trial and ('successes=' in trial[-1].group(0) or trial[-1].group(2)=='PASSED'):
        m=trial[-1];parts=dict((k,int(v)) for k,v in re.findall(r'(\w+)=(\d+)',m.group(3) or ''))
        counts={'total':int(m.group(1)),'passed':parts.get('successes',0),'failed':parts.get('failures',0),
            'error':parts.get('errors',0),'skipped':parts.get('skips',0),'expected_failures':parts.get('expectedFailures',0),
            'unexpected_successes':parts.get('unexpectedSuccesses',0)}
        if not parts and m.group(2)=='PASSED':counts['passed']=counts['total']
        framework='twisted_trial'
    stestr=list(re.finditer(r'^Ran: (\d+) tests in [^\n]+\n((?:\s+- [A-Za-z ]+: \d+\s*\n)+)',text,re.M))
    if not framework and stestr:
        m=stestr[-1];p={k:int(v) for k,v in re.findall(r'- ([A-Za-z ]+): (\d+)',m.group(2))}
        required={'Passed','Skipped','Expected Fail','Unexpected Success','Failed'}
        if required<=p.keys():
            counts={'total':int(m.group(1)),'passed':p['Passed'],'failed':p['Failed'],'error':p.get('Errors',0),
                'skipped':p['Skipped'],'expected_failures':p['Expected Fail'],'unexpected_successes':p['Unexpected Success']}
            framework='stestr_subunit'
    totals=list(re.finditer(r'^Total: (\d+) tests, (\d+) failures, (\d+) errors and (\d+) skipped in [^\n]+$',text,re.M))
    layers=list(re.finditer(r'^\s*Ran (\d+) tests with (\d+) failures, (\d+) errors and (\d+) skipped in [^\n]+$',text,re.M))
    if not framework and (totals or len(layers)==1):
        m=totals[-1] if totals else layers[0];total,failed,error,skipped=map(int,m.groups())
        counts={'total':total,'passed':total-failed-error-skipped,'failed':failed,'error':error,'skipped':skipped}
        framework='zope_testrunner'
    if not framework:return original
    result={'parser_version':PARSER_VERSION,'recognized':False,'framework':framework,
        'counts':counts,'failure_nodes':[],'error_nodes':[],'exit_code':exit_code,'pass':None}
    if counts['total']<=0 or any(v<0 for v in counts.values()):return result
    if sum(v for k,v in counts.items() if k!='total')!=counts['total']:return result
    failures=counts['failed']+counts['error']+counts.get('unexpected_successes',0)
    if counts['passed']+failures<=0:return result
    if (exit_code==0 and failures) or (exit_code==1 and not failures):
        result['contradictory_exit_summary']=True;return result
    result.update(recognized=True,**{'pass':exit_code==0 and not failures})
    return result
