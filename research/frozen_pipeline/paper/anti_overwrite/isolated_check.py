"""Runs inside an explicitly requested offline container; not imported on host."""
import ast
import json
import os
import runpy
import sys
import traceback


def target_line_event(frame, event, filename, span, name, is_class=False):
    """A one-line function call counts; executing its definition does not."""
    if event != 'line' or os.path.realpath(frame.f_code.co_filename) != filename:
        return False
    if not span[0] <= frame.f_lineno <= span[1]:
        return False
    if is_class:
        # Class-span coverage includes methods and executed class-body lines,
        # but not the enclosing module merely executing the class declaration.
        return frame.f_code.co_name != '<module>'
    return frame.f_code.co_name == name


def main():
    target = json.load(open('/owned/target.json'))
    filename = os.path.realpath('/repo/' + target['path'])
    names = target['symbol'].split('.')
    nodes = ast.parse(open(filename).read()).body
    node = None
    for name in names:
        matches = [n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
        if len(matches) != 1:
            print('TRACER_RESULT=' + json.dumps({'status': 'unknown', 'target_reached': False, 'error': 'target_symbol_unresolved'}))
            return
        node = matches[0]
        nodes = node.body
    span = (node.lineno, max(getattr(n, 'lineno', node.lineno) for n in ast.walk(node)))
    state = {'status': 'unknown', 'target_reached': False, 'target_symbol': target['symbol']}
    def trace(frame, event, arg):
        # Do not trace every dependency/import line when only this source is
        # a coverage target. A later call into the target still invokes this
        # global hook, including calls made by an untraced caller.
        if event == 'call' and os.path.realpath(frame.f_code.co_filename) != filename:
            return None
        if target_line_event(frame, event, filename, span, node.name, isinstance(node, ast.ClassDef)):
            state['target_reached'] = True
        return trace
    sys.settrace(trace)
    try:
        runpy.run_path('/owned/check.py', run_name='__main__')
        state['status'] = 'pass'
    except AssertionError:
        state.update(status='fail', exception_type='AssertionError')
    except BaseException as exc:
        state.update(status='unknown', exception_type=type(exc).__name__, error=str(exc)[:500])
    finally:
        sys.settrace(None)
    print('TRACER_RESULT=' + json.dumps(state, sort_keys=True))


if __name__ == '__main__':
    main()
