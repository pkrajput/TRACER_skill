"""Discover retained source writers from inventory, ASTs and recorded actions.

No nomination/origin/oracle labels are accessed by discovery. No subject code runs.
"""
import argparse
import ast
from collections import Counter, defaultdict
from functools import lru_cache
import json
from pathlib import Path
import posixpath
import re
import shlex

if __package__:
    from .helper_ast import analyze
    from .structure import sha, fingerprint
    from .swe import Archive, read_jsonl, save, jsonl
else:
    from helper_ast import analyze
    from structure import sha, fingerprint
    from swe import Archive, read_jsonl, save, jsonl


def normalize(path, cwd='/testbed'):
    return posixpath.normpath(path if path.startswith('/') else posixpath.join(cwd, path))


def snapshot_ref(snapshot, path):
    if path.startswith('/testbed/'):
        return snapshot['files'].get(path[len('/testbed/'):], 'BASE')
    return snapshot.get('tmp_files', {}).get(path)


def shell_commands(command):
    """Remove heredoc bodies before tokenizing; never search their string content.

    Bounded shell syntax: simple commands, separators, cd, direct Python scripts.
    Shell functions, substitutions, pipelines and nested shells are unsupported.
    """
    lines = command.splitlines()
    kept, terminators = [], []
    for line in lines:
        if terminators:
            delimiter, tabs = terminators[0]
            if (line.lstrip('\t') if tabs else line) == delimiter:
                terminators.pop(0)
            continue
        matches = list(re.finditer(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\2", line))
        terminators.extend((m.group(3), bool(m.group(1))) for m in matches)
        kept.append(line)
    lexer = shlex.shlex('\n'.join(kept), posix=True, punctuation_chars=';&|<>\n')
    lexer.whitespace = ' \t\r'
    lexer.commenters = '#'
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    result, current = [], []
    for token in tokens:
        if token and all(c in ';&|\n' for c in token):
            if current:
                result.append(current)
            current = []
        else:
            current.append(token)
    if current:
        result.append(current)
    return result


def invocations(command):
    cwd = '/testbed'
    found = []
    for words in shell_commands(command):
        while words and re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', words[0]):
            words = words[1:]
        if not words:
            continue
        if words[0] == 'cd' and len(words) == 2 and not any(c in words[1] for c in '$`~'):
            cwd = normalize(words[1], cwd)
        elif re.fullmatch(r'python(?:[23](?:\.\d+)?)?', posixpath.basename(words[0])):
            args = words[1:]
            while args and args[0] in {'-u', '-B', '-O', '-OO', '-s', '-S', '-E', '-I'}:
                args = args[1:]
            if args and not args[0].startswith('-') and args[0].endswith('.py') and not any(c in args[0] for c in '$`~'):
                found.append(dict(path=normalize(args[0], cwd), cwd=cwd,
                                  argv=words, shell_attribution='syntactic_direct_invocation'))
    return found


def literal_creation_before_invocation(command, path, source_sha256):
    """Resolve a quoted literal heredoc immediately followed by Python invocation.

    Require exact archived bytes. Unquoted/expanding heredocs and intervening
    commands do not establish the invoked version. This is syntax inspection,
    not shell execution or a general shell semantics implementation.
    """
    lines = command.splitlines(keepends=True)
    cwd = '/testbed'
    for i, line in enumerate(lines):
        # The supported producer is a standalone cat redirection, not a string
        # nested inside Python, echo, a shell function or another heredoc.
        cd_prefix = re.match(r'\s*(cd\s+[^;&|\n]+\s*&&)\s*', line)
        header = line[cd_prefix.end():] if cd_prefix else line
        m = re.fullmatch(r"\s*cat\s+>\s*(\S+)\s*<<\s*(['\"])([A-Za-z_][A-Za-z_0-9]*)\2\s*\n?", header)
        if not m:
            continue
        try:
            dest = shlex.split(m.group(1))[0]
        except (ValueError, IndexError):
            continue
        # Prefix may only contain cd for this narrow ordering proof.
        prefix = shell_commands(''.join(lines[:i]) + (cd_prefix.group(1) if cd_prefix else ''))
        if any(not (w[0] == 'cd' and len(w) == 2) for w in prefix):
            continue
        cwd = '/testbed'
        for w in prefix:
            cwd = normalize(w[1], cwd)
        if normalize(dest, cwd) != path:
            continue
        for j in range(i + 1, len(lines)):
            if lines[j].rstrip('\r\n') != m.group(3):
                continue
            body = ''.join(lines[i+1:j])
            if sha(body) != source_sha256:
                break
            tail = shell_commands(''.join(lines[j+1:]))
            if not tail:
                break
            calls = invocations('cd ' + shlex.quote(cwd) + '\n' + shlex.join(tail[0]))
            return len(calls) == 1 and calls[0]['path'] == path
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--archive', type=Path, required=True)
    ap.add_argument('--batch', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--base-manifest', type=Path, help='Previously cached immutable base sources; no network fetches')
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=False)
    eligible = {r['run_id'] for r in read_jsonl(args.batch / 'endpoint_census_final.jsonl')
                if r['benchmark'] == 'swebench' and r['eligible']}
    # Deliberately discard all previous labels at the input boundary.
    inventory = [{k: r[k] for k in ('run_id', 'path', 'final_content_sha256', 'stratum', 'task')}
                 for r in read_jsonl(args.batch / 'file_inventory.jsonl') if r['run_id'] in eligible]
    assert len({(r['run_id'], r['path']) for r in inventory}) == len(inventory)
    archive = Archive(args.archive, args.batch, args.out)
    bases = json.loads(args.base_manifest.read_text()) if args.base_manifest else {}
    used_bases = {}
    by_run = defaultdict(list)
    for row in inventory:
        by_run[row['run_id']].append(row)
    analyses, outputs, run_inputs = {}, [], {}

    @lru_cache(maxsize=4096)
    def ast_info(ref):
        if ref in (None, 'BASE'):
            return None, 'source_unavailable_or_base_not_loaded'
        try:
            return fingerprint(ast.parse(archive.blob(ref))), None
        except (SyntaxError, ValueError) as exc:
            return None, str(exc)

    def ast_hash(ref):
        return ast_info(ref)[0]

    for index, (runid, rows) in enumerate(sorted(by_run.items())):
        events = sorted(archive.run(runid, 'events.jsonl'), key=lambda e: e['sequence'])
        snapshots = {s['snapshot_id']: s for s in archive.run(runid, 'snapshots.jsonl')}
        final = json.loads((args.batch / 'inputs/swebench' / runid / 'final.json').read_text())
        initial = json.loads((args.batch / 'inputs/swebench' / runid / 'initial.json').read_text())
        instance = json.loads((args.batch / 'inputs/swebench' / runid / 'instance.json').read_text())
        run_inputs[runid] = dict(events_sha256=sha(json.dumps(events, sort_keys=True)),
            snapshots_sha256=sha(json.dumps(snapshots, sort_keys=True)),
            initial_sha256=sha(json.dumps(initial, sort_keys=True)),
            final_sha256=sha(json.dumps(final, sort_keys=True)),
            instance_sha256=sha(json.dumps(instance, sort_keys=True)))
        calls = defaultdict(list)
        for e in events:
            for call in invocations(e.get('command') or ''):
                calls[call['path']].append((e, call))
        for row in rows:
            path = normalize(row['path'])
            final_ref = snapshot_ref(final, path)
            assert final_ref == row['final_content_sha256'], (runid, path)
            record = dict(row, initial_ref=snapshot_ref(initial, path), final_sha256=final_ref,
                          python_supported=path.endswith('.py'), versions=[], invocations=[],
                          history_links=[], helper_transitions=[], detected=False)
            if not record['python_supported']:
                outputs.append(record)
                continue
            version_events = defaultdict(list)
            for e in events:
                for side in ('before_snapshot', 'after_snapshot'):
                    snap = snapshots.get(e.get(side))
                    if snap:
                        ref = snapshot_ref(snap, path)
                        if ref not in (None, 'BASE'):
                            version_events[ref].append(e['sequence'])
            version_events[final_ref]
            for ref, sequences in version_events.items():
                if ref not in analyses:
                    analyses[ref] = analyze(archive.blob(ref))
                result = analyses[ref]
                record['versions'].append(dict(sha256=ref, first_sequence=min(sequences) if sequences else None,
                    last_sequence=max(sequences) if sequences else None, endpoint=ref == final_ref,
                    ast_sha256=ast_hash(ref), parse_error=result['parse_error'],
                    effects=result['effects'], unknown_calls=result['unknown_calls']))
            previous = snapshot_ref(initial, path)
            for e in events:
                snap = snapshots.get(e.get('after_snapshot'))
                if not snap:
                    continue
                ref = snapshot_ref(snap, path)
                if ref == previous:
                    continue
                a, b = ast_hash(previous), ast_hash(ref)
                status = 'ast_changed' if a and b and a != b else 'ast_same' if a and b else 'introduced_removed_or_unavailable'
                record['helper_transitions'].append(dict(event_id=e['event_id'], sequence=e['sequence'],
                    before_ref=previous, after_ref=ref, before_ast=a, after_ast=b, status=status))
                previous = ref
            for e, call in calls[path]:
                before, after = snapshots.get(e.get('before_snapshot')), snapshots.get(e.get('after_snapshot'))
                invocation = dict(event_id=e['event_id'], sequence=e['sequence'], exit_code=e.get('exit_code'), **call)
                record['invocations'].append(invocation)
                if not before or not after:
                    invocation['source_status'] = 'missing_snapshots'
                    continue
                rb, ra = snapshot_ref(before, path), snapshot_ref(after, path)
                if ra not in (None, 'BASE') and literal_creation_before_invocation(e.get('command') or '', path, ra):
                    ref, status = ra, 'exact_literal_written_immediately_before_invocation'
                elif rb == ra and rb not in (None, 'BASE'):
                    ref, status = rb, 'same_version_before_after'
                else:
                    invocation['source_status'] = 'ambiguous_changed_or_missing_invoked_version'
                    continue
                invocation['source_status'] = status
                invocation['source_sha256'] = ref
                for effect in analyses[ref]['effects']:
                    for target in effect['paths']:
                        target = normalize(target, call['cwd'])
                        if not target.startswith('/testbed/') or not target.endswith('.py') or target == path:
                            continue
                        tb, ta = snapshot_ref(before, target), snapshot_ref(after, target)
                        if ta in (None, 'BASE') or tb == ta:
                            continue
                        (ha, ea), (hb, eb) = ast_info(ta), ast_info(tb)
                        base_key = f"{instance['repo']}@{instance['base_commit']}:{target[len('/testbed/'):] }"
                        if tb == 'BASE' and base_key in bases and not bases[base_key].get('error'):
                            entry = bases[base_key]
                            data = Path(entry['cached']).read_bytes()
                            assert sha(data) == entry['sha256']
                            used_bases[base_key] = entry
                            try:
                                hb = fingerprint(ast.parse(data.decode('utf-8')))
                                eb = None
                            except (SyntaxError, ValueError) as exc:
                                eb = str(exc)
                        record['history_links'].append(dict(event_id=e['event_id'], sequence=e['sequence'],
                            helper_sha256=ref, helper_version_status=status, helper_endpoint_same_bytes=ref == final_ref,
                            target=target[len('/testbed/'):], before_ref=tb, after_ref=ta,
                            target_after_ast=ha, target_before_ast=hb,
                            before_parse_error=eb, after_parse_error=ea,
                            ast_change='changed' if ha and hb and ha != hb else 'same' if ha and hb else 'before_or_after_unavailable',
                            exit_code=e.get('exit_code'), effect=effect,
                            read_same_target=any(normalize(p, call['cwd']) == target for p in effect['reads']),
                            attribution='matching_static_write_and_change_in_invocation_interval'))
            record['endpoint_static_source_writer'] = any(
                p.endswith('.py') for effect in analyses[final_ref]['effects'] for p in effect['paths'])
            record['any_version_static_source_writer'] = any(
                p.endswith('.py') for v in record['versions'] for ef in v['effects'] for p in ef['paths'])
            record['detected'] = bool(record['history_links'])
            outputs.append(record)
        print(index + 1, '/', len(by_run), runid, flush=True)
    jsonl(args.out / 'discovery.jsonl', outputs)
    save(args.out / 'base_sources_used.json', used_bases)
    save(args.out / 'run_input_hashes.json', run_inputs)
    save(args.out / 'summary.json', dict(eligible_runs=len(eligible), inventory_runs=len(by_run),
        inventory_files=len(outputs), language_extensions=dict(Counter(Path(r['path']).suffix for r in outputs)),
        python_files=sum(r['python_supported'] for r in outputs),
        endpoint_parse_errors=sum(any(v['endpoint'] and v['parse_error'] for v in r['versions']) for r in outputs),
        endpoint_static_writers=sum(r.get('endpoint_static_source_writer', False) for r in outputs),
        historical_static_writers=sum(r.get('any_version_static_source_writer', False) for r in outputs),
        detected_files=sum(r['detected'] for r in outputs),
        detected_runs=len({r['run_id'] for r in outputs if r['detected']}),
        detected_strata=dict(Counter(r['stratum'] for r in outputs if r['detected'])),
        history_links=sum(len(r['history_links']) for r in outputs),
        input_hashes={n: sha((args.batch/n).read_bytes()) for n in ['file_inventory.jsonl', 'endpoint_census_final.jsonl']},
        script_hashes={n:sha(Path(__file__).with_name(n).read_bytes()) for n in ['discover_helpers.py', 'helper_ast.py', 'swe.py', 'structure.py']},
        archive=str(args.archive),
        limitations=['Captured new-file inventory, not all repository files.',
                     'Bounded possible-effect AST analysis and simple-shell invocation parser.',
                     'Action snapshots support interval association, not isolated causal attribution.',
                     'No deletion-safety inference; nominations are not detector input.']))
    print((args.out / 'summary.json').read_text())


if __name__ == '__main__':
    main()
