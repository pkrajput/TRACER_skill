"""Remove source documentation without changing executable AST structure.

Docstring removal intentionally changes __doc__. Locations/blank lines and every
non-documentation token remain intact. Empty documentation-only suites get pass.
"""
import ast
import copy
import hashlib
import io
import tokenize


def executable_tree(source):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr) and
                    isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
                body.pop(0)
                if not body and not isinstance(node, ast.Module):
                    body.append(ast.Pass())
    return ast.dump(tree, include_attributes=False)


def strip_documentation(source):
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines: offsets.append(offsets[-1] + len(line))
    def pos(row, col, byte=False):
        if byte:
            col = len(lines[row-1].encode('utf-8')[:col].decode('utf-8'))
        return offsets[row-1] + col
    replacements = []
    comments = 0
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            replacements.append((pos(*tok.start), pos(*tok.end), ''))
            comments += 1
    docstrings = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr) and
                    isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
                doc = body[0]
                replacement = 'pass' if len(body) == 1 and not isinstance(node, ast.Module) else ''
                # A same-line semicolon would leave an empty statement; pass is a no-op.
                tail = lines[doc.end_lineno-1][len(lines[doc.end_lineno-1].encode()[:doc.end_col_offset].decode()):]
                if tail.lstrip().startswith(';'):
                    raise ValueError('same-line docstring suite requires explicit review')
                replacements.append((pos(doc.lineno,doc.col_offset,True),
                                     pos(doc.end_lineno,doc.end_col_offset,True),replacement))
                docstrings += 1
    cleaned = source
    for start,end,value in sorted(replacements, reverse=True):
        old = source[start:end]
        blank = ''.join('\n' if c == '\n' else '\r' if c == '\r' else ' ' for c in old)
        cleaned = cleaned[:start] + value + blank[len(value):] + cleaned[end:]
    before,after = executable_tree(source),executable_tree(cleaned)
    if before != after:
        raise ValueError('executable AST changed while removing documentation')
    return cleaned, {'comments_removed':comments,'docstrings_removed':docstrings,
                     'executable_ast_equal':True,'doc_attribute_changed':docstrings > 0,
                     'original_sha256':hashlib.sha256(source.encode()).hexdigest(),
                     'clean_sha256':hashlib.sha256(cleaned.encode()).hexdigest(),
                     'executable_ast_sha256':hashlib.sha256(before.encode()).hexdigest()}
