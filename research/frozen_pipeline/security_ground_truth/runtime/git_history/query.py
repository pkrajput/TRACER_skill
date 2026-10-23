"""Read Git objects as data; never check out, import, or execute target source."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tokenize

from ..history.adapter import canonical, sha, structural_index, structural_delta

FULL_SHA = re.compile(r'^[0-9a-f]{40}$')


def safe_git_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1')
    return env


class GitHistoryView:
    """An ancestry-constrained view over a bare repository, with B2/B3 packaging.

    Histories follow the first-parent path at the requested cutoff. Renames are
    reported but never followed automatically; recreation of a path starts a
    new identity. Other ancestor branches can be queried explicitly by SHA.
    """

    def __init__(self, repository: Path | str, cutoff: str, arm: str = 'B3', *,
                 source_url: str | None = None, max_blob_bytes: int = 2_000_000):
        self.repository = Path(repository).resolve()
        if arm not in {'B2', 'B3', 'B4'}:
            raise ValueError('Git view arm must be B2, B3 or B4')
        if not FULL_SHA.fullmatch(cutoff):
            raise ValueError('Cutoff must be an immutable full 40-character commit SHA')
        self.arm, self.cutoff, self.source_url = arm, cutoff, source_url
        self.max_blob_bytes = max_blob_bytes
        if (self.repository / 'info/grafts').exists() or (self.repository / 'objects/info/alternates').exists():
            raise ValueError('Grafts and alternate object stores are not permitted')
        if self._git('rev-parse', '--is-bare-repository').strip() != b'true':
            raise ValueError('A bare data-only Git cache is required')
        if self._git('rev-parse', '--is-shallow-repository').strip() != b'false':
            raise ValueError('Shallow history cannot establish complete cutoff ancestry')
        if self._git('cat-file', '-t', cutoff).strip() != b'commit':
            raise ValueError('Cutoff must identify a commit object')
        self._ancestors = frozenset(self._git('rev-list', cutoff).decode().splitlines())
        self._ancestry_by_limit = {cutoff: self._ancestors}
        self._metadata_cache, self._file_cache, self._structure_cache = {}, {}, {}
        self.view = {'arm': arm, 'history_channel': 'git', 'cutoff_commit': cutoff}

    def _git(self, *args: str, check: bool = True) -> bytes | int:
        command = ['git', '--no-replace-objects', '--no-optional-locks',
                   '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                   '-c', 'core.attributesFile=/dev/null', '--git-dir='+str(self.repository), *args]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=safe_git_environment(), timeout=90)
        if check and result.returncode:
            raise ValueError('Git object query failed: '+result.stderr.decode(errors='replace').strip())
        if not check:
            return result.returncode
        return result.stdout

    def _allowed(self, commit: str | None, before: str | None = None) -> str:
        commit = commit or self.cutoff
        if not isinstance(commit, str) or not FULL_SHA.fullmatch(commit) or commit not in self._ancestors:
            raise ValueError('Requested commit is not an allowed full-SHA cutoff ancestor')
        limit = before or self.cutoff
        if limit not in self._ancestors:
            raise ValueError('Requested commit exceeds the query ancestry cutoff')
        if limit not in self._ancestry_by_limit:
            ancestors = frozenset(self._git('rev-list', limit).decode().splitlines())
            if not ancestors.issubset(self._ancestors):
                raise ValueError('Query ancestry is inconsistent with the frozen cutoff')
            self._ancestry_by_limit[limit] = ancestors
        if commit not in self._ancestry_by_limit[limit]:
            raise ValueError('Requested commit exceeds the query ancestry cutoff')
        return commit

    @staticmethod
    def _path(path: str) -> str:
        if not isinstance(path, str) or not path or any(ord(c) < 32 for c in path) or '\\' in path:
            raise ValueError('Expected a literal repository-relative path')
        if path.startswith('/project/'):
            path = path[len('/project/'):]
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or '..' in parsed.parts or not parsed.parts or path.startswith(':'):
            raise ValueError('Path escapes the repository or contains Git pathspec syntax')
        if parsed.parts[0].casefold() == '.git' or str(parsed) != path:
            raise ValueError('Noncanonical or Git-internal path')
        return path

    def provenance(self) -> dict:
        return {'history_channel': 'git', 'repository_cache': str(self.repository),
                'source_url': self.source_url, 'cutoff_commit': self.cutoff,
                'allowed_ancestor_count': len(self._ancestors),
                'allowed_ancestor_set_sha256': sha('\n'.join(sorted(self._ancestors))+'\n'),
                'ancestry_policy': 'inclusive ancestors of immutable cutoff; dates are not access controls',
                'history_selection': 'first-parent path changes; no automatic rename following',
                'source_execution': False, 'agent_reasoning_available': False}

    def _metadata(self, commit: str) -> dict:
        self._allowed(commit)
        if commit not in self._metadata_cache:
            raw = self._git('show', '-s', '--format=%H%x00%P%x00%ct%x00%B', commit)
            ident, parents, timestamp, message = raw.split(b'\0', 3)
            parent_ids = parents.decode().split()
            for parent in parent_ids:
                self._allowed(parent, commit)
            self._metadata_cache[commit] = {'commit': ident.decode(), 'parents': parent_ids,
                                           'committer_timestamp': int(timestamp),
                                           'message': message.decode('utf-8', errors='replace').rstrip('\n'),
                                           'message_bytes_sha256': sha(message),
                                           'message_source': 'original_git_commit_metadata_not_agent_rationale'}
        return dict(self._metadata_cache[commit])

    def _file(self, commit: str, path: str) -> dict:
        self._allowed(commit)
        key = (commit, path)
        if key in self._file_cache:
            return dict(self._file_cache[key])
        raw = self._git('ls-tree', '-z', commit, '--', ':(literal)'+path)
        entries = [item for item in raw.split(b'\0') if item]
        if not entries:
            result = {'status': 'path_absent', 'source': '', 'source_sha256': None, 'blob_sha1': None}
        elif len(entries) != 1:
            raise ValueError('Literal path did not resolve uniquely')
        else:
            metadata, returned_path = entries[0].split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            if returned_path.decode() != path:
                raise ValueError('Git returned a different path')
            if kind != 'blob' or mode not in {'100644', '100755'}:
                result = {'status': 'non_regular_file_not_followed', 'source': '',
                          'source_sha256': None, 'blob_sha1': blob, 'mode': mode}
            elif int(self._git('cat-file', '-s', blob)) > self.max_blob_bytes:
                result = {'status': 'blob_exceeds_data_limit', 'source': '',
                          'source_sha256': None, 'blob_sha1': blob, 'mode': mode}
            else:
                payload = self._git('cat-file', 'blob', blob)
                try:
                    encoding = tokenize.detect_encoding(io.BytesIO(payload).readline)[0] if path.endswith(('.py', '.pyi')) else 'utf-8'
                    source = payload.decode(encoding)
                    status = 'available'
                except (SyntaxError, UnicodeError, LookupError):
                    source, encoding, status = '', None, 'source_encoding_error'
                result = {'status': status, 'source': source, 'source_sha256': sha(payload),
                          'blob_sha1': blob, 'mode': mode, 'source_encoding': encoding,
                          'source_fidelity': 'exact_git_blob_decoded_with_declared_source_encoding'}
        self._file_cache[key] = result
        return dict(result)

    def rename_candidates(self, commit: str, path: str) -> dict:
        commit, path = self._allowed(commit), self._path(path)
        parents = self._metadata(commit)['parents']
        if len(parents) != 1:
            return {'status': 'root_or_merge_no_single_parent_link', 'automatic_follow': False, 'candidates': []}
        raw = self._git('diff-tree', '--no-renames', '--no-abbrev', '--raw', '-r', '-z', parents[0], commit)
        parts = [part for part in raw.split(b'\0') if part]
        changes = []
        for offset in range(0, len(parts), 2):
            meta = parts[offset].decode().split()
            changes.append({'status': meta[-1], 'old_blob': meta[2], 'new_blob': meta[3],
                            'path': parts[offset+1].decode()})
        additions = [entry for entry in changes if entry['path'] == path and entry['status'] == 'A']
        if not additions:
            return {'status': 'not_a_path_addition', 'automatic_follow': False, 'candidates': []}
        candidates = sorted(entry['path'] for entry in changes if entry['status'] == 'D' and entry['old_blob'] == additions[0]['new_blob'])
        status = 'ambiguous_exact_blob_rename' if len(candidates) > 1 else 'exact_blob_rename_candidate' if candidates else 'new_path_or_unresolved_rename'
        return {'status': status, 'automatic_follow': False, 'candidates': candidates,
                'commit': commit, 'parent': parents[0], 'evidence': 'identical blob in deleted paths; no semantic rename claim'}

    def _lineage(self, path: str, before_commit: str | None = None) -> tuple[list[str], dict]:
        limit = self._allowed(before_commit)
        args = ['log', '--first-parent', '--full-history', '--no-renames', '--format=%H']
        changes = self._git(*args, limit, '--', ':(literal)'+path).decode().splitlines()
        additions = self._git(*args, '--diff-filter=A', limit, '--', ':(literal)'+path).decode().splitlines()
        boundary = additions[0] if additions else None
        if boundary in changes:
            changes = changes[:changes.index(boundary)+1]
        selected = list(dict.fromkeys([limit]+changes))
        for commit in selected:
            self._allowed(commit, limit)
        note = {'query_cutoff': limit, 'first_parent_only': True, 'path_identity_boundary': boundary,
                'rename': self.rename_candidates(boundary, path) if boundary else None,
                'automatic_rename_following': False}
        return list(reversed(selected)), note

    def _diff(self, commit: str, path: str) -> str:
        parents = self._metadata(commit)['parents']
        options = ['--no-ext-diff', '--no-textconv', '--no-renames', '--ignore-submodules=all']
        if parents:
            raw = self._git('diff', *options, parents[0], commit, '--', ':(literal)'+path)
        else:
            raw = self._git('show', '--format=', '--root', *options, commit, '--', ':(literal)'+path)
        return raw.decode('utf-8', errors='replace')

    def _structure(self, source: dict, path: str) -> dict:
        key = (source['blob_sha1'], path)
        if key not in self._structure_cache:
            self._structure_cache[key] = structural_index(source['source'], path) if source['status'] == 'available' else {'parse_status': source['status'], 'symbols': [], 'calls': [], 'guards': []}
        return self._structure_cache[key]

    def rationale_for(self, event_ids=None) -> dict:
        return {'status': 'not_recorded_in_git', 'events': [],
                'note': 'Commit messages are Git metadata, not captured developer or agent reasoning.'}

    def relevant_symbol_history(self, path: str, symbol: str | None = None, *,
                                before_message: int | None = None, before_commit: str | None = None,
                                max_states: int = 4, max_history_chars: int = 16000,
                                max_rationale_chars: int = 4000) -> dict:
        if before_message is not None:
            raise ValueError('Agent message indices cannot be used as Git cutoffs; use before_commit')
        path = self._path(path)
        timeline, lineage = self._lineage(path, before_commit)
        max_states = min(20, max(0, max_states))
        max_history_chars = min(100000, max(0, max_history_chars))
        chosen = timeline[-max_states:] if max_states else []
        per_state = max_history_chars // max(1, len(chosen))
        states, previous = [], None
        for commit in chosen:
            source, metadata = self._file(commit, path), self._metadata(commit)
            diff = self._diff(commit, path)
            item = {'state_id': 'git:'+commit+':'+path, 'commit': commit, 'path': path,
                    'source_sha256': source['source_sha256'], 'blob_sha1': source['blob_sha1'],
                    'source_status': source['status'], 'source_fidelity': source.get('source_fidelity'),
                    'commit_parents': metadata['parents'], 'committer_timestamp': metadata['committer_timestamp'],
                    'commit_message': metadata['message'][:per_state//5],
                    'commit_message_clipped': len(metadata['message']) > per_state//5,
                    'commit_message_sha256': metadata['message_bytes_sha256'],
                    'message_source': metadata['message_source'], 'diff_parent_policy': 'first_parent',
                    'ancestor_of_cutoff_verified': True}
            if self.arm == 'B2':
                text = source['source']
                item['raw_diff'] = diff[:per_state//3]
                item['raw_diff_clipped'] = len(diff) > per_state//3
                item['evidence_kind'] = 'raw_git_file_diff_and_commit_metadata'
            else:
                structure = self._structure(source, path)
                matches = [s for s in structure['symbols'] if symbol is None or s['qualified_name'] == symbol or s['name'] == symbol]
                ambiguous = symbol is not None and len(matches) > 1
                item['symbol_resolution'] = 'ambiguous_symbol_name' if ambiguous else 'found' if matches else 'not_found'
                item['symbols'] = matches
                scopes = {s['qualified_name'] for s in matches}
                item['calls'] = [c for c in structure['calls'] if c['scope'] in scopes]
                item['guards'] = [g for g in structure['guards'] if g['scope'] in scopes]
                item['parse_status'] = structure['parse_status']
                item['structural_delta'] = structural_delta(previous, structure)
                if symbol is not None:
                    prior_matches = [s for s in (previous or {}).get('symbols', [])
                                     if s['qualified_name'] == symbol or s['name'] == symbol]
                    relevant_scopes = scopes | {s['qualified_name'] for s in prior_matches}
                    for key in ('introduced_symbols', 'removed_symbols', 'changed_symbols'):
                        item['structural_delta'][key] = [name for name in item['structural_delta'][key] if name in relevant_scopes]
                    item['structural_delta']['scope_filter'] = 'queried_symbol_names_only'
                item['structural_delta']['comparison_scope'] = 'adjacent_selected_file_observations_not_necessarily_adjacent_commits'
                item['evidence_kind'] = 'syntax_linked_git_file_history'
                lines = source['source'].splitlines()
                text = '\n\n'.join('\n'.join(lines[s['start_line']-1:s['end_line']]) for s in matches)
                previous = structure
            cap = max(0, per_state-len(json.dumps(item, ensure_ascii=False)))
            item['source_fragment'] = text[:cap]
            item['source_fragment_clipped'] = len(text) > cap
            states.append(item)
        shared = {'history_channel': 'git', 'path': path, 'symbol': symbol,
                  'available_state_count': len(timeline), 'selected_state_count': len(states), 'states': states,
                  'edit_records': [], 'recorded_edit_count': 0, 'semantic_flow_available': False,
                  'complete_repository_states': False, 'lineage': lineage,
                  'selection_policy': 'same latest path-change states for B2/B3; no outcome or symbol-change oracle',
                  'provenance': self.provenance()}
        return {'arm': self.arm, 'history': shared, 'shared_history_sha256': sha(canonical(shared)),
                'selected_state_ids_sha256': sha(canonical([s['state_id'] for s in states])),
                'rationale': self.rationale_for(),
                'bounds': {'max_history_chars': max_history_chars, 'max_rationale_chars': 0,
                           'note': 'Text fragments are bounded; schema and syntax lists add overhead. Caller enforces final prompt tokens.'}}

    def history_for_path(self, path: str, *, before_commit: str | None = None,
                         max_states: int = 8, include_source: bool = False) -> dict:
        result = self.relevant_symbol_history(path, before_commit=before_commit, max_states=max_states)
        if not include_source:
            for state in result['history']['states']:
                state.pop('source_fragment', None)
        return result

    def symbol_at(self, path: str, symbol: str, *, commit: str | None = None) -> dict:
        if self.arm == 'B2':
            raise ValueError('Structured retrieval is disabled for B2')
        path, commit = self._path(path), self._allowed(commit)
        source = self._file(commit, path)
        structure = self._structure(source, path)
        matches = [s for s in structure['symbols'] if s['qualified_name'] == symbol or s['name'] == symbol]
        lines = source['source'].splitlines()
        return {'status': 'ambiguous_symbol_name' if len(matches) > 1 else 'found' if matches else 'symbol_not_found',
                'history_channel': 'git', 'commit': commit, 'path': path,
                'matches': [{**s, 'source': '\n'.join(lines[s['start_line']-1:s['end_line']])} for s in matches],
                'source_sha256': source['source_sha256'], 'ancestor_of_cutoff_verified': True,
                'semantic_flow_available': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--cutoff', required=True)
    parser.add_argument('--arm', choices=['B2', 'B3', 'B4'], default='B3')
    parser.add_argument('--path', required=True)
    parser.add_argument('--symbol')
    parser.add_argument('--max-states', type=int, default=4)
    args = parser.parse_args()
    result = GitHistoryView(args.repository, args.cutoff, args.arm).relevant_symbol_history(args.path, args.symbol, max_states=args.max_states)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
