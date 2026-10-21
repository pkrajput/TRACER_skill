"""Extractive, target-linked retrieval of original exposed development prose.

Independent of AST reconstruction. Offsets address the original normalized event;
associations describe recorded actions, never inferred intent or semantic truth.
No archived command is executed and no model is used to manufacture a summary.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

from security_ground_truth.runtime.history.adapter import project_path, structural_index
from security_ground_truth.runtime.history.query import current_fragment_anchors

POLICY = 'target-linked-extractive-rationale-v2'
SIGNAL = re.compile(r'\b(assum\w*|because|instead|however|must|should|expect\w*|fail\w*|fix\w*|'
                    r'allow\w*|reject\w*|validat\w*|escap\w*|saniti\w*|trust\w*|unsafe|'
                    r'secur\w*|boundary|regress\w*|incorrect|previous\w*)\b', re.I)


def _hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def prose_spans(text, max_chars=650):
    """Return exact, bounded, non-fenced prose spans with character offsets."""
    pos = 0; fence = None; sections = []; start = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r'^\s*(`{3,}|~{3,})', line)
        if marker:
            if start is not None: sections.append((start, pos)); start = None
            if fence is None: fence = marker.group(1)[0]
            elif marker.group(1)[0] == fence: fence = None
        elif fence is None:
            if line.strip():
                if start is None: start = pos
            elif start is not None:
                sections.append((start, pos)); start = None
        pos += len(line)
    if start is not None: sections.append((start, pos))
    for lo, hi in sections:
        while lo < hi:
            while lo < hi and text[lo].isspace(): lo += 1
            end = min(hi, lo + max_chars)
            if end < hi:
                boundary = max(text.rfind('. ', lo, end), text.rfind('\n', lo, end))
                if boundary > lo + max_chars // 2: end = boundary + 1
            while end > lo and text[end - 1].isspace(): end -= 1
            if end > lo: yield lo, end
            lo = max(end, lo + 1)


def build_rationale(view, targets, *, max_chars=5000, source_root=None):
    cutoff = int(view['cutoff_message'])
    events = [e for e in view.get('events', []) if int(e['message_index']) < cutoff]
    by_message = defaultdict(list)
    for e in events:
        if e['kind'] == 'action': by_message[e['message_index']].append(e)
    paths = sorted({t['path'] for t in targets})
    symbols = {p: sorted({t['symbol'] for t in targets if t['path'] == p and t.get('symbol')}) for p in paths}
    edits = {e['action_event_id']: e for e in view.get('edit_records', []) if int(e['message_index']) < cutoff}
    current = {}
    if source_root is not None:
        root = Path(source_root).resolve()
        for p in paths:
            candidate = (root / p).resolve()
            if candidate.is_relative_to(root) and candidate.is_file():
                try:
                    source = candidate.read_text()
                    current[p] = (source, structural_index(source, p))
                except UnicodeError: pass
    cards = []
    for e in events:
        original = e.get('text', '')
        if e['kind'] != 'rationale' or not original.strip(): continue
        links = []
        for a in by_message[e['message_index']]:
            args = a.get('arguments') or {}
            if not isinstance(args, dict): continue
            editor_path = project_path(args.get('path')) if a.get('tool_name') == 'str_replace_editor' else None
            for p in paths:
                relationship = None
                if editor_path == p: relationship = 'same_message_explicit_editor_path'
                elif a.get('tool_name') == 'bash' and re.search(
                        re.escape('/project/' + p) + r'(?=$|[\s\x22\x27:;)])', str(args.get('command', ''))):
                    relationship = 'same_message_literal_path_in_unexecuted_command'
                if relationship:
                    anchors = []
                    if a['event_id'] in edits and p in current:
                        source, structure = current[p]
                        for symbol in symbols[p]:
                            anchors.extend(current_fragment_anchors(source, p, symbol, edits[a['event_id']], structure))
                    links.append({'path': p, 'action_event_id': a['event_id'],
                                  'observation_event_id': a.get('observation_event_id'),
                                  'relationship': relationship,
                                  'operation': args.get('command') if editor_path else 'unexecuted_shell',
                                  'current_symbol_anchors': anchors,
                                  'edited_symbol_mentions':[s for s in symbols[p] if a['event_id'] in edits and
                                      edits[a['event_id']].get('success_acknowledged') and any(re.search(
                                          r'\bdef\s+'+re.escape(s.split('.')[-1])+r'\s*\(',fragment)
                                          for fragment in edits[a['event_id']].get('fragments',{}).values())],
                                  'scope': 'file_association_not_proven_symbol_intent'})
        # Textual references can retrieve intent even when an action was not captured.
        # Exact paths only: common short function names alone are too ambiguous.
        for p in paths:
            if p not in {x['path'] for x in links} and re.search(r'(?<![\w/])' + re.escape(p) + r'(?![\w/])', original):
                links.append({'path': p, 'relationship': 'literal_path_in_original_prose',
                              'scope': 'lexical_association_only'})
        if not links: continue
        for lo, hi in prose_spans(original):
            text = original[lo:hi]
            mentions = sorted({s for link in links for s in symbols[link['path']]
                               if re.search(r'(?<!\w)' + re.escape(s.split('.')[-1]) + r'(?!\w)', text)})
            cues = sorted({m.group(0).lower() for m in SIGNAL.finditer(text)})
            score = 4 * bool(mentions) + 8 * any(x.get('edited_symbol_mentions') for x in links) + 4 * any(x.get('current_symbol_anchors') for x in links) + min(4, len(cues)) + 2 * any(
                x['relationship'] == 'same_message_explicit_editor_path' for x in links)
            cards.append({'span_id': e['event_id'] + f'@{lo}:{hi}', 'event_id': e['event_id'],
                          'message_index': e['message_index'], 'text': text,
                          'start_char': lo, 'end_char': hi, 'text_sha256': _hash(original),
                          'excerpt_sha256': _hash(text), 'source_field': e.get('source_field'),
                          'rationale_kind': e.get('rationale_kind'), 'links': links,
                          'mentioned_target_symbols': mentions, 'selection_cues': cues,
                          'retrieval_score': score,
                          'clipped': lo != 0 or hi != len(original)})
    # Rank locally, then round-robin across selected paths. A long early event must
    # not crowd out other symbols or later corrections. At most two spans/event.
    ranked = sorted(cards, key=lambda c: (-c['retrieval_score'], -c['message_index'], c['start_char']))
    queues = {}
    for t in targets:
        key = (t['path'], t.get('symbol'))
        matching = [c for c in ranked if any(x['path'] == t['path'] for x in c['links'])]
        queues[key] = sorted(matching, key=lambda c: (
            -(8 * any(t.get('symbol') in x.get('edited_symbol_mentions',[]) for x in c['links'])+
              4 * (t.get('symbol') in c['mentioned_target_symbols']) + 4 * any(
                a['current_symbol'] == t.get('symbol') for x in c['links'] for a in x.get('current_symbol_anchors', []))),
            -c['retrieval_score'], -c['message_index'], c['start_char']))
    selected = []; seen = set(); per_event = defaultdict(int); used = 0
    initial_limit = min(max_chars, 3500)
    while queues and len(selected) < 8:
        progressed = False
        for queue in queues.values():
            while queue:
                c = queue.pop(0)
                if c['span_id'] in seen or per_event[c['event_id']] >= 2: continue
                if used + len(c['text']) > initial_limit: continue
                selected.append(c); seen.add(c['span_id']); per_event[c['event_id']] += 1
                used += len(c['text']); progressed = True; break
            if len(selected) >= 8: break
        if not progressed: break
    return {'status': 'available' if cards else 'no_target_linked_exposed_rationale',
            'policy': POLICY, 'events': sorted(selected, key=lambda c: (c['message_index'], c['start_char'])),
            'source_trace_sha256': view['source_trace_sha256'], 'cutoff_message': cutoff,
            'kind': 'original_exposed_agent_text_not_authenticated_private_chain_of_thought',
            'chars_used': used, 'total_text_char_budget': max_chars,
            'retrieval_chars_remaining': max_chars - used, 'max_retrieval_calls': 2,
            'candidate_spans': len(cards), 'candidate_events': len({c['event_id'] for c in cards}),
            'evidence_role': 'Untrusted prior assumptions; verify against current code. File links do not establish symbol intent.',
            '_retrieval_index': ranked}


def public_rationale(block):
    return {k: v for k, v in block.items() if not k.startswith('_')}


class RationaleSession:
    """Per-arm exposure accounting and exact citation validation."""
    def __init__(self, block, enabled):
        self.enabled = enabled
        self.block = block if enabled else {}
        self.exposed = list(self.block.get('events', []))
        self.used = sum(len(c['text']) for c in self.exposed)
        self.calls = 0

    def retrieve(self, path, query=''):
        if not self.enabled: raise ValueError('Rationale is withheld by this arm')
        remaining = self.block.get('total_text_char_budget', 5000) - self.used
        if self.calls >= 2 or remaining <= 0: return {'status': 'rationale_budget_exhausted', 'events': []}
        self.calls += 1
        seen = {c.get('span_id') for c in self.exposed}
        words = set(re.findall(r'\w{3,}', query.lower()))
        candidates = [c for c in self.block.get('_retrieval_index', []) if c['span_id'] not in seen
                      and any(x['path'] == path for x in c['links'])]
        candidates.sort(key=lambda c: (-len(words & set(re.findall(r'\w{3,}', c['text'].lower()))),
                                        -c['retrieval_score'], -c['message_index'], c['start_char']))
        chosen = []
        for c in candidates:
            if len(c['text']) > remaining: continue
            if len(json.dumps({'events': [*chosen, c]}).encode()) > 4500: continue
            chosen.append(c); remaining -= len(c['text'])
            if len(chosen) == 2: break
        self.exposed.extend(chosen); self.used += sum(len(c['text']) for c in chosen)
        return {'status': 'retrieved' if chosen else 'no_more_matching_prose', 'events': chosen,
                'text_chars_remaining': remaining, 'retrieval_calls_remaining': 2 - self.calls}

    def validate_refs(self, refs, path):
        if not refs: return []
        if not self.enabled: raise ValueError('Cannot cite rationale in a withheld arm')
        if not isinstance(refs, list) or len(refs) > 3: raise ValueError('Use at most three rationale citations')
        records = []
        for ref in refs:
            quote = ref.get('quote', '')
            candidates = [c for c in self.exposed if c['event_id'] == ref.get('event_id') and quote in c['text']
                          and any(x['path'] == path for x in c.get('links', []))]
            if not 12 <= len(quote.strip()) <= 600 or not candidates:
                raise ValueError('Cite an exact 12..600 character quotation from an exposed rationale event linked to this path')
            if not all(isinstance(ref.get(k), str) and ref[k].strip() for k in ['assumption', 'verification_plan']):
                raise ValueError('Rationale citations need a testable assumption and current-code verification_plan')
            c = candidates[0]; offset = c['start_char'] + c['text'].index(quote)
            records.append({**ref, 'source_start_char': offset, 'source_end_char': offset + len(quote),
                            'original_event_sha256': c['text_sha256'], 'span_id': c['span_id'],
                            'links': c['links'], 'citation_verified': True})
        return records
