"""Bounded Python AST write-effect analysis; never executes analyzed code.

Abstract values carry constant strings, file handles, read origins and operations.
Branches are joined; loops are approximated once. Effects are possible effects,
not a sound or complete Python analysis. History must corroborate every finding.
"""
import ast
import copy
from dataclasses import dataclass, field


@dataclass
class Value:
    strings: set = field(default_factory=set)
    handles: set = field(default_factory=set)
    reads: set = field(default_factory=set)
    operations: set = field(default_factory=set)

    def join(self, *others):
        values = (self, *others)
        return Value(*(set().union(*(getattr(v, k) for v in values))
                       for k in ('strings', 'handles', 'reads', 'operations')))


class Analyzer:
    def __init__(self):
        self.env = {}
        self.functions = {}
        self.active = set()
        self.effects = []
        self.unknown_calls = set()
        self.context = []
        self.aliases = {'open': 'open'}

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + '.' + node.attr
        return ''

    def expr(self, node):
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return Value(strings={node.value} if isinstance(node.value, str) else set())
        if isinstance(node, ast.Name):
            return self.env.get(node.id, Value())
        if isinstance(node, (ast.Lambda, ast.GeneratorExp)):
            return Value()  # Deferred bodies are not executed by their creation.
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            args = [self.expr(a) for a in node.args]
            kw = {k.arg: self.expr(k.value) for k in node.keywords}
            combined = Value().join(*args, *kw.values())
            receiver = self.expr(node.func.value) if isinstance(node.func, ast.Attribute) else Value()
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ''
            if name in {'open', 'io.open'}:
                paths = args[0].strings if args else kw.get('file', Value()).strings
                modes = args[1].strings if len(args) > 1 else kw.get('mode', Value(strings={'r'})).strings
                return Value(handles={(p, m) for p in paths for m in modes})
            if name in {'pathlib.Path', 'Path'}:
                return Value(strings=set(args[0].strings) if args else set())
            if method == 'open' and receiver.strings:
                modes = args[0].strings if args else kw.get('mode', Value(strings={'r'})).strings
                return Value(handles={(p, m) for p in receiver.strings for m in modes})
            if method in {'read', 'readlines', 'read_text', 'read_bytes'}:
                paths = {p for p, m in receiver.handles if 'r' in m or '+' in m}
                if method in {'read_text', 'read_bytes'}:
                    paths |= receiver.strings
                return Value(reads=paths, operations={method})
            if method in {'write', 'writelines', 'write_text', 'write_bytes'}:
                paths = {p for p, m in receiver.handles if any(x in m for x in 'wax+')}
                if method in {'write_text', 'write_bytes'}:
                    paths |= receiver.strings
                data = args[0] if args else kw.get('data', Value())
                self.effects.append(dict(line=node.lineno, end_line=node.end_lineno,
                    paths=sorted(paths), reads=sorted(data.reads),
                    operations=sorted(data.operations), sink=method,
                    context=list(self.context), resolved=bool(paths)))
                return Value()
            if name in self.functions and name not in self.active:
                fn = self.functions[name]
                old = self.env
                self.env = copy.deepcopy(old)
                for param, val in zip(fn.args.args, args):
                    self.env[param.arg] = val
                self.active.add(name)
                self.context.append('called_function:' + name)
                self.block(fn.body)
                self.context.pop()
                self.active.remove(name)
                self.env = old
                return Value()  # Return-value and global effects are unsupported.
            if method in {'append', 'extend', 'insert'}:
                value = receiver.join(combined)
                value.strings = set()
                value.operations.add(method)
                if isinstance(node.func.value, ast.Name):
                    self.env[node.func.value.id] = value
                return Value()
            value = receiver.join(combined)
            value.strings = set()  # Never guess the result of a dynamic transform.
            if method or name:
                value.operations.add(method or name)
            if name not in {'print', 'len', 'range', 'enumerate', 'str', 'int', 're.sub', 're.subn', 're.search', 'sys.exit'} and method not in {'replace', 'split', 'splitlines', 'join', 'strip', 'lstrip', 'rstrip', 'startswith', 'endswith', 'group'}:
                self.unknown_calls.add(name or ast.unparse(node.func))
            return value
        children = [self.expr(c) for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
        value = Value().join(*children)
        value.strings = set()
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            a, b = children[:2]
            if a.strings and b.strings and len(a.strings) * len(b.strings) <= 32:
                sep = '/' if isinstance(node.op, ast.Div) else ''
                value.strings = {x + sep + y for x in a.strings for y in b.strings}
            value.operations.add('concatenate' if isinstance(node.op, ast.Add) else 'path_join')
        elif isinstance(node, ast.Subscript):
            value.operations.add('subscript')
        return value

    def assign(self, target, value):
        if isinstance(target, ast.Name):
            self.env[target.id] = copy.deepcopy(value)
            self.aliases[target.id] = '<bound:' + target.id + '>'
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self.assign(t, value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            name = target.value.id
            value = self.env.get(name, Value()).join(value)
            value.operations.add('subscript_assignment')
            value.strings = set()
            self.env[name] = value

    def branches(self, branches, label):
        initial = copy.deepcopy(self.env)
        states = [initial]
        for body in branches:
            self.env = copy.deepcopy(initial)
            self.context.append(label)
            self.block(body)
            self.context.pop()
            states.append(self.env)
        self.env = {k: Value().join(*(s.get(k, Value()) for s in states))
                    for k in set().union(*(s.keys() for s in states))}

    def block(self, body):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = '<function:' + node.name + '>'
                self.aliases[node.name] = name
                self.functions[name] = node
            elif isinstance(node, ast.ClassDef):
                continue  # Deferred methods are not treated as executed code.
            elif isinstance(node, ast.Import):
                for n in node.names:
                    self.aliases[n.asname or n.name] = n.name
            elif isinstance(node, ast.ImportFrom):
                for n in node.names:
                    self.aliases[n.asname or n.name] = (node.module or '') + '.' + n.name
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = self.expr(node.value)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.assign(target, value)
            elif isinstance(node, ast.AugAssign):
                self.assign(node.target, self.expr(node.target).join(self.expr(node.value)))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expr(item.context_expr)
                    if item.optional_vars:
                        self.assign(item.optional_vars, value)
                self.block(node.body)
            elif isinstance(node, ast.If):
                self.expr(node.test)
                self.branches([node.body, node.orelse], 'conditional')
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(node, ast.While):
                    self.expr(node.test)
                else:
                    self.assign(node.target, self.expr(node.iter))
                self.branches([node.body, node.orelse], 'loop_once')
            elif isinstance(node, ast.Try):
                self.branches([node.body] + [h.body for h in node.handlers], 'try_branch')
                self.block(node.orelse)
                self.block(node.finalbody)
            elif isinstance(node, ast.Expr):
                self.expr(node.value)
            elif isinstance(node, (ast.Return, ast.Raise)):
                self.expr(getattr(node, 'value', None))


def analyze(source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return dict(parse_error=str(exc), effects=[], unknown_calls=[])
    a = Analyzer()
    a.block(tree.body)
    return dict(parse_error=None, effects=a.effects, unknown_calls=sorted(a.unknown_calls))
