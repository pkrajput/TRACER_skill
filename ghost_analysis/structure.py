"""Conservative AST identity and source-string extraction. Never executes source."""
import ast
import copy
import hashlib

DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def fingerprint(node, strip_docs=False):
    if strip_docs:
        node = copy.deepcopy(node)
        for n in ast.walk(node):
            if isinstance(n, (*DEFS, ast.Module)) and n.body and isinstance(n.body[0], ast.Expr):
                v = n.body[0].value
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    n.body = n.body[1:]
    return sha(ast.dump(node, include_attributes=False))


def definitions(source):
    tree = ast.parse(source)
    found = []
    def visit(node, scope=(), parent=None):
        if isinstance(node, DEFS):
            name = (*scope, node.name)
            found.append(dict(qualified_name=".".join(name), name=node.name,
                kind=type(node).__name__, start_line=node.lineno, end_line=node.end_lineno,
                ast_sha256=fingerprint(node), code_ast_sha256=fingerprint(node, True),
                parent=parent, nodes=sum(1 for _ in ast.walk(node))))
            parent, scope = ".".join(name), name
        for child in ast.iter_child_nodes(node):
            visit(child, scope, parent)
    visit(tree)
    return found


def literal_definitions(text):
    """Parse an indented source fragment without rewriting its string values.

    Dedenting an entire fragment also changes whitespace *inside* multiline
    string constants. A synthetic statement wrapper preserves those values.
    """
    try:
        return definitions(text)
    except IndentationError:
        found = definitions('if True:\n' + text)
        for d in found:
            d['start_line'] -= 1
            d['end_line'] -= 1
        return found


def payloads(source):
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    out = []
    for literal in ast.walk(tree):
        if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
            continue
        text = literal.value.strip('\r\n')
        if not any(t in text for t in ["def ", "class "]):
            continue
        names = []
        parent = parents.get(literal)
        if isinstance(parent, ast.Assign):
            names = [n.id for t in parent.targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        roles = set()
        def uses(expr):
            return any(n is literal or isinstance(n, ast.Name) and n.id in names for n in ast.walk(expr))
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            method = call.func.attr
            if method == "replace" and len(call.args) >= 2:
                if uses(call.args[0]): roles.add("search_pattern")
                if uses(call.args[1]): roles.add("replacement_argument")
            if method in {"insert", "append", "extend", "write", "write_text", "writelines"}:
                if any(uses(a) for a in call.args): roles.add(method + "_argument")
        record = dict(literal_line=literal.lineno, literal_end_line=literal.end_lineno,
                      names=names, roles=sorted(roles) or ["unresolved"], text=text,
                      text_sha256=sha(text))
        try:
            record["definitions"] = literal_definitions(text)
            record["parse_error"] = None
        except (SyntaxError, ValueError) as exc:
            record["definitions"] = []
            record["parse_error"] = str(exc)
        out.append(record)
    return out


def state_at(unit, candidates):
    same = [u for u in candidates if u["qualified_name"] == unit["qualified_name"]]
    if len(same) > 1:
        return "ambiguous_duplicate_definition"
    if not same:
        return "absent_or_renamed"
    return "current" if same[0]["ast_sha256"] == unit["ast_sha256"] else "superseded"


def maximal_matches(matches):
    """Do not count both a matched class/function and its matched descendants."""
    return [m for m in matches if not any(
        other is not m and m["target_unit"]["qualified_name"].startswith(other["target_unit"]["qualified_name"] + ".")
        and other["target_unit"]["start_line"] <= m["target_unit"]["start_line"]
        and other["target_unit"]["end_line"] >= m["target_unit"]["end_line"]
        for other in matches)]
