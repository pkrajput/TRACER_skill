"""Resolve citations against current source, with actionable recovery evidence.

Whitespace normalization compares Python tokens: string contents, names and
operators must still match. No approximate/fuzzy semantic matching is allowed.
"""
import ast
import hashlib
import io
import re
import tokenize
import textwrap


def source_hash(source):
    return hashlib.sha256(source.encode()).hexdigest()


def symbols(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    rows = []

    def walk(node, parents=()):
        for child in ast.iter_child_nodes(node):
            scope = parents
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = (*parents, child.name)
                rows.append({'symbol': '.'.join(scope), 'start_line': child.lineno,
                             'end_line': child.end_lineno})
            walk(child, scope)
    walk(tree)
    return rows


def _tokens(text):
    ignored = {tokenize.ENCODING, tokenize.NEWLINE,
               tokenize.NL, tokenize.ENDMARKER}
    # Strip displayed line numbers only when every nonblank line has one.
    lines = text.splitlines()
    if lines and all(not s.strip() or re.match(r'^\s*\d+: ', s) for s in lines):
        text = '\n'.join(re.sub(r'^\s*\d+: ', '', s) for s in lines)
    # Normalize common indentation while retaining relative block structure and
    # whitespace INSIDE literals via tokens.
    try:
        text = textwrap.dedent(text).strip()
        return [(t.type, '<indent>' if t.type == tokenize.INDENT else t.string)
                for t in tokenize.generate_tokens(io.StringIO(text).readline)
                if t.type not in ignored]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []


def matching_quote(source, quote, scope=None):
    """Return a unique current-source slice; ambiguous matches are rejected."""
    lines = source.splitlines()
    lo, hi = (scope['start_line'], scope['end_line']) if scope else (1, len(lines))
    bounded = '\n'.join(lines[lo-1:hi])
    if quote.strip() and bounded.count(quote) == 1:
        start = lo + bounded[:bounded.index(quote)].count('\n')
        return quote, start, start + quote.count('\n'), 'exact_quote'
    wanted = _tokens(quote)
    if not wanted:
        return None
    # Keep matches within the original quote's line count. This prevents a short
    # quote from accidentally accepting arbitrary extra statements.
    width = len(quote.strip().splitlines())
    matches = []
    for index in range(lo-1, hi-width+1):
        candidate = '\n'.join(lines[index:index+width])
        if _tokens(candidate) == wanted:
            matches.append((candidate, index+1, index+width, 'token_equivalent_whitespace'))
    return matches[0] if len(matches) == 1 else None


def resolve(source, action, hypothesis, reads):
    """Bind current source ourselves; model hashes and symbol names are hints.

    A quote must still match current code. A valid range identifies current code
    even when the model's optional hash/symbol is wrong. Neither asserts truth.
    """
    digest = source_hash(source)
    scopes=symbols(source);hint=action.get('evidence_symbol','')
    matches=[s for s in scopes if s['symbol']==hint or s['symbol'].split('.')[-1]==hint]
    scope=matches[0] if len(matches)==1 else None
    quote = action.get('evidence_quote', '')
    start, end = action.get('evidence_start_line'), action.get('evidence_end_line')
    if action.get('line_range'):
        start,end=action['line_range']
    # A unique quote wins over stale line numbers. Never fuzzy-match operators
    # or literal contents; ambiguous unqualified quotes still require a range.
    match=matching_quote(source,quote) if quote.strip() else None
    if not match and scope and quote.strip():match=matching_quote(source,quote,scope)
    if match:
        quote,start,end,mode=match
    elif start is not None or end is not None:
        end = start if end is None else end
        if (type(start) is not int or type(end) is not int or
                not 1 <= start <= end <= len(source.splitlines()) or end-start >= 160):
            raise ValueError('Citation range is outside current source or exceeds 160 lines')
        quote = '\n'.join(source.splitlines()[start-1:end]);mode='auto_bound_current_range'
    elif quote.strip():
        raise ValueError('Citation text is absent or ambiguous in current source; supply its path and line range')
    else:
        return None
    enclosing=[s for s in scopes if s['start_line']<=start<=end<=s['end_line']]
    scope=min(enclosing,key=lambda s:s['end_line']-s['start_line']) if enclosing else None
    return {'evidence_quote': quote, 'evidence_start_line': start,
            'evidence_end_line': end, 'source_sha256': digest,
            'evidence_symbol': scope['symbol'] if scope else '<module>', 'resolution': mode,
            'binding_owner':'harness',
            'model_hash_corrected':bool(action.get('evidence_source_sha256') and action['evidence_source_sha256']!=digest),
            'model_symbol_corrected':bool(hint and (not scope or hint!=scope['symbol']))}


def resolve_in_editor(editor,action,hypothesis,reads):
    """Allow evidence in a downstream file, not only the hypothesis's file.

    Explicit path wins. Legacy actions without a path can bind a unique quote
    among actually inspected files, or an unambiguous inspected symbol/range.
    Hashes never select a file. Ambiguity requires an explicit path.
    """
    if action.get('path'):
        path=action['path'];value=resolve(editor.text(path),action,hypothesis,reads.get(path,[]))
        return {**value,'path':path} if value else None
    target=hypothesis['path'];quote=action.get('evidence_quote','');matched=[]
    for path in sorted(editor.read_paths|{target}):
        source=editor.text(path)
        if quote.strip() and matching_quote(source,quote):
            value=resolve(source,action,hypothesis,reads.get(path,[]))
            matched.append({**value,'path':path})
    if len(matched)==1:return matched[0]
    if len(matched)>1:
        target_match=[v for v in matched if v['path']==target]
        if len(target_match)==1:return target_match[0]
        raise ValueError('Evidence matches multiple inspected files; provide path explicitly')
    hint=action.get('evidence_symbol')
    if hint:
        for path in sorted(editor.read_paths):
            source=editor.text(path)
            scopes=[s for s in symbols(source) if s['symbol']==hint or s['symbol'].split('.')[-1]==hint]
            for scope in scopes:
                lo=action.get('evidence_start_line');hi=action.get('evidence_end_line',lo)
                if type(lo) is int and type(hi) is int and scope['start_line']<=lo<=hi<=scope['end_line']:
                    value=resolve(source,action,hypothesis,reads.get(path,[]));matched.append({**value,'path':path})
        if len(matched)==1:return matched[0]
    value=resolve(editor.text(target),action,hypothesis,reads.get(target,[]))
    return {**value,'path':target} if value else None


def recovery(editor, action, hypotheses, read_versions):
    """Deliver a fresh usable read on rejection; no approval/assessment is invented."""
    h = hypotheses.get(action.get('hypothesis_id'), {})
    path = action.get('path') or h.get('path')
    result = {'instruction': 'Use the current anchors below; do not repeat the rejected action unchanged.',
              'hypothesis_ids': list(hypotheses)[-12:]}
    if not path:
        return result
    try:
        source = editor.text(path)
    except (ValueError, UnicodeError):
        result['available_paths'] = sorted(editor.read_paths)[:12]
        return result
    lines = source.splitlines()
    line = action.get('evidence_start_line') or h.get('line') or 1
    old = action.get('old') or h.get('target_line_text')
    if old and source.count(old) == 1:
        line = source[:source.index(old)].count('\n')+1
    elif old and source.count(old)>1:
        offsets=[m.start() for m in re.finditer(re.escape(old),source)]
        candidates=[source[:i].count('\n')+1 for i in offsets]
        line=min(candidates,key=lambda n:abs(n-int(line)))
        result['ambiguous_match_lines']=candidates[:12]
        result['edit_instruction']='Include unchanged surrounding lines in old/new so the edit identifies one occurrence.'
    line = max(1, min(int(line), max(1, len(lines))))
    lo, hi = max(1, line-4), min(len(lines), line+7)
    snippet = '\n'.join(lines[lo-1:hi])
    # Never advertise a truncated line as a usable citation.
    while len(snippet) > 2400 and hi > lo:
        hi -= 1; snippet = '\n'.join(lines[lo-1:hi])
    if len(snippet) > 2400:
        return {**result, 'path': path, 'instruction': 'Current line exceeds recovery budget; read a narrower target.'}
    digest = source_hash(source)
    read_versions.setdefault(path, []).append((digest, lo, hi))
    editor.read_paths.add(path)
    anchors = [s for s in symbols(source) if s['start_line'] <= line <= s['end_line']]
    result.update(path=path, source_sha256=digest, source=snippet,
                  start_line=lo, end_line=hi, symbol_anchors=anchors[-4:],
                  citation_fields={'evidence_start_line': lo, 'evidence_end_line': hi,
                                   'evidence_source_sha256': digest})
    if action.get('action')=='edit' and source.count(snippet)==1:
        result['unique_current_edit_context']=snippet
    if h.get('rationale_refs'):
        result['required_rationale_checks'] = [r['event_id'] for r in h['rationale_refs']]
    return result
