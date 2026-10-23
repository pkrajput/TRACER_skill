"""Explicit, recorded method-scope normalization for archived replacements."""
import ast
import copy


def normalized_nodes(code, target):
    tree = ast.parse(code)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    main = next(n for n in functions if n.name == target)
    called = {n.func.attr for n in ast.walk(main) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
              and n.func.value.id == 'self'}
    moved = []
    for node in list(main.body):
        if (isinstance(node, ast.FunctionDef) and node.name.startswith('_')
                and node.args.args and node.args.args[0].arg == 'self'
                and node.name in called):
            main.body.remove(node)
            functions.append(node)
            moved.append(node.name)
    names = [n.name for n in functions]
    if len(names) != len(set(names)):
        raise ValueError('ambiguous duplicate method names')
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    if len(imports) + len([n for n in tree.body if isinstance(n, ast.FunctionDef)]) != len(tree.body):
        raise ValueError('replacement contains non-declarative top-level code')
    return imports, functions, moved


def component_source(code, symbol, imports):
    if '.' not in symbol:
        return imports + code, {'hoisted': [], 'method_adapter': False}
    target = symbol.rsplit('.', 1)[1]
    extra, methods, moved = normalized_nodes(code, target)
    owner = ast.ClassDef(name='_TracerComponent', bases=[], keywords=[], body=methods,
                         decorator_list=[])
    alias = ast.Assign(targets=[ast.Name(id=target, ctx=ast.Store())],
                       value=ast.Attribute(value=ast.Name(id='_TracerComponent', ctx=ast.Load()),
                                           attr=target, ctx=ast.Load()))
    tree = ast.Module(body=ast.parse(imports).body + extra + [owner, alias], type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n', {
        'hoisted': moved, 'class_methods': [m.name for m in methods], 'method_adapter': True}


def splice_method(full_source, symbol, code):
    """Place replacement helpers in the actual class, without changing their bodies."""
    tree = ast.parse(full_source)
    names = symbol.split('.')
    nodes = tree.body
    for name in names[:-1]:
        owner = next(n for n in nodes if isinstance(n, ast.ClassDef) and n.name == name)
        nodes = owner.body
    target = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == names[-1])
    extra, methods, moved = normalized_nodes(code, names[-1])
    existing = {n.name for n in nodes if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n is not target}
    if existing.intersection(m.name for m in methods):
        raise ValueError('replacement helper would overwrite an existing class member')
    i = nodes.index(target)
    nodes[i:i+1] = copy.deepcopy(methods)
    # Imports remain module-global, including helpers formerly emitted after the method.
    pos = 1 if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) else 0
    while pos < len(tree.body) and isinstance(tree.body[pos], ast.ImportFrom) and tree.body[pos].module == '__future__':
        pos += 1
    tree.body[pos:pos] = extra
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n', moved
