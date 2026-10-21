"""In-container probe recorder. Compatible with older benchmark Pythons.

Generated observations are investigator evidence, never independent labels.
Line tracing covers this Python process only, not native calls or subprocesses.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import traceback
import ast
import math
import reprlib
from itertools import islice


def target_line_matches(target, path, line, code_name):
    """Class targets include method execution within the attested AST span."""
    if not target or path != target.get('path'):
        return False
    if target.get('kind') == 'class':
        return target.get('start_line', 0) <= line <= target.get('end_line', 0)
    return (code_name == target.get('symbol', '').split('.')[-1]
            and target.get('start_line', 0) < line <= target.get('end_line', 0))


def observation_value(value, depth=0, seen=None):
    """Bounded JSON-compatible observations; serialization must not kill a probe."""
    seen = set() if seen is None else seen
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {'type': 'float', 'repr': str(value)}
    if isinstance(value, str):
        return value if len(value) <= 2000 else {'type': 'str', 'prefix': value[:2000], 'length': len(value)}
    if id(value) in seen:
        return {'type': type(value).__name__, 'summary': '<cycle>'}
    if depth >= 4:
        return {'type': type(value).__name__, 'summary': '<depth limit>'}
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            items = list(islice(value.items(),20))
            return {'type': 'dict', 'items': [[observation_value(k, depth+1, seen),
                                              observation_value(v, depth+1, seen)] for k, v in items],
                    'omitted_items': max(0, len(value)-20)}
        if isinstance(value, (list, tuple, set, frozenset)):
            return {'type': type(value).__name__,
                    'items': [observation_value(x, depth+1, seen) for x in islice(iter(value), 20)],
                    'omitted_items': max(0, len(value)-20)}
        try:
            summary = reprlib.repr(value)[:2000]
        except Exception as error:
            summary = '<repr failed: ' + type(error).__name__ + '>'
        return {'type': type(value).__name__, 'repr': summary}
    finally:
        seen.discard(id(value))


def configure_probe_environment(check):
    """Initialize Django utilities only if neither project nor check configured it.

    Minimal settings are explicitly recorded assumptions, never a substitute for
    an application's authorization/database configuration. No hidden tests read.
    """
    text = Path(check).read_text()
    tree = ast.parse(text)
    imports_django = any((isinstance(n, ast.ImportFrom) and (n.module or '').split('.')[0] == 'django') or
                        (isinstance(n, ast.Import) and any(a.name.split('.')[0] == 'django' for a in n.names))
                        for n in ast.walk(tree))
    if not imports_django:
        return {'django': 'not_requested'}
    if 'settings.configure' in text or 'django.setup' in text or 'DJANGO_SETTINGS_MODULE' in text:
        return {'django': 'check_manages_configuration'}
    import django
    from django.conf import settings
    mode = 'existing_project_configuration'
    if not settings.configured and not os.environ.get('DJANGO_SETTINGS_MODULE'):
        settings.configure(SECRET_KEY='tracer-local-probe-only', INSTALLED_APPS=[],
                           DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
                           USE_TZ=True, DEFAULT_CHARSET='utf-8')
        mode = 'minimal_utility_settings_not_application_configuration'
    from django.apps import apps
    if not apps.ready:
        django.setup()
    return {'django': mode, 'apps_ready': apps.ready,
            'limitation': 'Minimal settings cannot establish application-level authentication or authorization behavior.'}


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute_probe(root, check, expected, output):
    root = Path(root).resolve()
    check = Path(check).resolve()
    output = Path(output).resolve()
    expected = json.loads(Path(expected).read_text())
    result = {"status": "not_started", "source_identity": "not_checked",
              "coverage": {}, "observations": [], "independent_ground_truth": False,
              "coverage_scope": "Python line events in this process only"}

    def mismatches():
        bad = []
        for row in expected["files"]:
            path = (root / row["path"]).resolve()
            if root not in path.parents or not path.is_file() or file_hash(path) != row["sha256"]:
                bad.append(row["path"])
        return bad

    phase = 'unclassified'

    def set_phase(value):
        nonlocal phase
        if value not in {'ordinary','mutated'}:
            raise ValueError('tracer_phase must be ordinary or mutated')
        phase=value

    def observe(property_name, value):
        if len(result["observations"]) >= 100:
            result['observations_omitted'] = result.get('observations_omitted', 0) + 1
            return
        encoded = observation_value(value)
        if len(json.dumps(encoded)) > 6000:
            encoded = {'type': type(value).__name__, 'json_prefix': json.dumps(encoded)[:5800], 'truncated': True}
        result["observations"].append({"property": str(property_name)[:500], "value": encoded,
                                       'original_type': type(value).__name__,'phase':phase})

    expected_paths = {row["path"] for row in expected["files"]}
    coverage = {}
    traced_files = {}
    target = expected.get('_tracer_trace_target') or {}
    caller_frames = {}
    caller_file_hashes = {}
    target_frames_seen = set()

    def record_target_callers(frame):
        result['target_frame_executed'] = True
        result[phase+'_target_frame_executed'] = True
        caller = frame.f_back
        for _ in range(16):
            if caller is None:break
            filename=caller.f_code.co_filename
            # A helper defined by the generated program is not a real consumer.
            if filename and not filename.startswith('<'):
                path=Path(filename).resolve()
                if path not in {check,Path(__file__).resolve()} and path.is_file():
                    relative=os.path.relpath(str(path),str(root))
                    if relative in expected_paths or 'site-packages' in path.parts:
                        if str(path) not in caller_file_hashes:
                            caller_file_hashes[str(path)]=file_hash(path)
                        symbol=getattr(caller.f_code,'co_qualname',caller.f_code.co_name)
                        if not (relative==target.get('path') and symbol.split('.')[-1]==target.get('symbol','').split('.')[-1]):
                            key=(str(path),symbol,caller.f_code.co_firstlineno,phase)
                            caller_frames[key]={'path':relative if relative in expected_paths else str(path),
                                'symbol':symbol,'line':caller.f_lineno,'source_sha256':caller_file_hashes[str(path)],
                                'source_scope':'attested_project' if relative in expected_paths else 'installed_dependency_hash_recorded',
                                'phase':phase,
                                'relationship':'runtime_ancestor_of_target'}
            caller=caller.f_back

    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if filename not in traced_files:
            # Decide once per filename, not on every executed dependency line.
            # Returning None for an excluded frame avoids its line tracing;
            # calls into project frames still invoke the global trace function.
            path = None
            if filename and not (filename.startswith("<") and filename.endswith(">")):
                relative = os.path.relpath(filename, str(root))
                if relative in expected_paths:
                    path = relative
            traced_files[filename] = path
        path = traced_files[filename]
        if path is None:
            return None
        if event == "line":
            coverage.setdefault(path, set()).add(frame.f_lineno)
            if target_line_matches(target, path, frame.f_lineno, frame.f_code.co_name):
                # Capture once per invocation, not on every loop iteration.
                # Remove on return so recycled frame ids do not hide later calls.
                if id(frame) not in target_frames_seen:
                    target_frames_seen.add(id(frame))
                    record_target_callers(frame)
        elif event == 'return':
            target_frames_seen.discard(id(frame))
        return trace

    old_trace, old_cwd, old_path = sys.gettrace(), os.getcwd(), list(sys.path)
    try:
        bad = mismatches()
        if bad:
            result.update(status="source_mismatch", mismatched_paths=bad[:100])
            return result
        result["source_identity"] = "expected_files_match"
        os.chdir(str(root))
        sys.path.insert(0, str(root))
        try:
            result['environment'] = configure_probe_environment(check)
            # Setup coverage must not be mistaken for target execution by a check.
            sys.settrace(trace)
            runpy.run_path(str(check), init_globals={"tracer_observe": observe,'tracer_phase':set_phase}, run_name="__main__")
            result["status"] = "completed"
        except BaseException as error:
            result.update(status="check_exception", exception_type=type(error).__name__,
                          traceback=traceback.format_exc()[-4000:])
            result['failure_stage'] = 'environment_setup' if 'environment' not in result else 'generated_check'
        finally:
            sys.settrace(old_trace)
        bad_after = mismatches()
        if bad_after:
            result.update(source_identity="source_modified_during_check", modified_paths=bad_after[:100])
        result["coverage"] = {path: sorted(lines) for path, lines in sorted(coverage.items())}
        result['target_caller_frames'] = list(caller_frames.values())[:40]
        result["identity_scope"] = "Every scanner-manifest file before and after; extra image files not attested"
        return result
    finally:
        sys.settrace(old_trace)
        sys.path[:] = old_path
        os.chdir(old_cwd)
        output.write_text(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    execute_probe(*sys.argv[1:])
