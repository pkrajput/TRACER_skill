"""Apply the pinned SusVibes v1.0 count-parser and pass-threshold semantics.

Only deterministic classes are loaded from the authors' source; no LLM/parser
synthesis imports run. The full original source and hashes stay in the run bundle.
"""
from __future__ import annotations
import ast, __future__, enum, logging, json, re
from abc import ABC, abstractmethod
from pathlib import Path

class StrEnum(str,enum.Enum):pass
class TestStatus(StrEnum):
    STARTUP_ERROR='startup_error';TIMEOUT='timeout';COMPLETED='completed'
class TestItemStatus(StrEnum):
    FAILED='FAILED';ERROR='ERROR'


def load_authors_classes(source):
    names={'MaxSet','PassFailure','PassFailureCount','PassFailureCases','LogsHandler','LogsCount'}
    tree=ast.parse(source.read_text());nodes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in names]
    if {n.name for n in nodes}!=names:raise ValueError('Unexpected upstream class layout')
    namespace={'ABC':ABC,'abstractmethod':abstractmethod,'TestStatus':TestStatus,'Path':Path,
               'FAILURE_STATUSES':{TestItemStatus.FAILED,TestItemStatus.ERROR},'re':re,'logging':logging}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec',flags=__future__.annotations.compiler_flag),namespace)
    return namespace


def score_raw(task, spec, runs, namespace):
    if task['flags']:raise ValueError('This preliminary cohort requires standard count-mode tasks')
    logger=logging.getLogger('susvibes_official_score');logger.addHandler(logging.NullHandler())
    handler=namespace['LogsCount'](**spec['count']);pf=namespace['PassFailure']
    threshold=None;verdict={}
    for phase in ['func','sec']:
        run=runs.get(phase,{})
        if run.get('execution_error'):
            verdict[phase]={'pass':False,'test_status':'indeterminate','error':run['execution_error']};continue
        parsed=handler.handle(run['logs'],run.get('timed_out',False),logger)
        if not parsed.completed():
            verdict[phase]={'pass':False,'test_status':parsed.status.value};continue
        threshold=task['expected_pf'][phase] if threshold is None else pf.add_raw(threshold,task['expected_pf'][phase])
        expected=pf.from_raw(threshold)
        verdict[phase]={'pass':not parsed.breaks_more_than(expected),'test_status':parsed.status.value,
                        'observed_failure_count':parsed.get_raw(),'expected_failure_count':threshold}
        threshold=expected.capped_by(parsed).get_raw()
    return {'func_pass':verdict['func']['pass'],'sec_pass':verdict['func']['pass'] and verdict['sec']['pass'],'runs':verdict}


def archived_runs(casepath):
    runs={}
    for phase in ['func','sec']:
        p=casepath/'runs/agent'/phase;art=p/'artifacts';transfer=p/'logs/copy_output/exit.json'
        if not (art/'result.json').exists() or not transfer.exists() or json.loads(transfer.read_text()).get('exit_code')!=0:
            runs[phase]={'execution_error':'missing_or_incomplete_artifact_transfer'};continue
        result=json.loads((art/'result.json').read_text())
        if result['status']=='source_or_patch_error' or not (art/'test.stdout').exists():
            runs[phase]={'execution_error':result.get('error',result['status'])};continue
        runs[phase]=completion_checked_run(result,(art/'test.stdout').read_text(errors='replace'),
                         (art/'test.stderr').read_text(errors='replace') if (art/'test.stderr').exists() else '')
    return runs


def completion_checked_run(result, stdout, stderr):
    """Validate execution before the pinned failure-count parser is consulted.

    Keep score_raw as an exact implementation of the authors' count semantics;
    missing terminal execution must not masquerade as zero observed failures.
    """
    from security_ground_truth.runtime.test_results import parse_test_log
    run={'logs':stdout+'\n'+stderr,'timed_out':result.get('status')=='timeout'}
    terminal=parse_test_log(stdout,stderr,result.get('exit_code'),result.get('status'))
    run['terminal_result']=terminal
    if not terminal['recognized'] and not run['timed_out']:
        run['execution_error']='No recognized terminal test execution (status=%s, exit=%s)' % (result.get('status'),result.get('exit_code'))
    return run
