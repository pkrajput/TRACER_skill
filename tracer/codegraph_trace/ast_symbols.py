"""Extract symbol spans from a file's *current* source, independent of the code graph.

The recorder diffs each step against a code graph that was indexed *before* the agent ran, so
brand-new symbols have no span in that graph and their changed lines get folded into the
nearest stale node (or the file node) instead of being recorded as their own. To fix that we
parse the post-step source directly and recover the true symbol spans, including the symbols
the agent just created.

This module is language-dispatched behind :func:`extract_symbols`:

- **Python** is handled with the standard library :mod:`ast` (no third-party dependency).
- **JavaScript / Java / CSS** are handled with tree-sitter when the grammar packages
  (``tree-sitter-javascript`` / ``tree-sitter-java`` / ``tree-sitter-css``) are installed. If
  tree-sitter or a grammar is unavailable, the language simply yields ``[]``.

Any unsupported language, missing parser, or unparseable source returns ``[]`` so the recorder
falls back to its previous graph-based behaviour (no regression).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from functools import lru_cache


# Map a Python AST node to the code-graph label vocabulary used elsewhere (see
# ``_SYMBOL_LABELS`` in :mod:`codegraph_trace.codegraph`).
_CLASS_LABEL = "Class"
_FUNCTION_LABEL = "Function"
_METHOD_LABEL = "Method"
_INTERFACE_LABEL = "Interface"
_ENUM_LABEL = "Enum"
_RULE_LABEL = "Rule"
_KEYFRAMES_LABEL = "Keyframes"

# File extension -> language key. Python uses the stdlib ``ast``; the rest use tree-sitter.
_EXT_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".css": "css",
}


@dataclass(frozen=True)
class AstSymbol:
    """One symbol recovered from live source.

    Attributes:
        name: The leaf identifier (e.g. ``method``).
        dotted_suffix: The dotted path relative to the module (e.g. ``Outer.method``). This is
            what gets appended to a module's qualified-name prefix to form a full
            ``qualified_name`` consistent with codebase-memory-mcp's naming.
        kind: One of ``Class`` / ``Function`` / ``Method`` (the code-graph label vocabulary).
        start_line: 1-based first line of the symbol's span.
        end_line: 1-based last line of the symbol's span (inclusive).
    """

    name: str
    dotted_suffix: str
    kind: str
    start_line: int
    end_line: int

    def span_size(self) -> int:
        """Number of source lines covered by this symbol (inclusive)."""
        return self.end_line - self.start_line


def language_for_path(path: str) -> str | None:
    """Return the language key for a path, or None when we have no symbol parser for it."""
    norm = (path or "").replace("\\", "/").lower()
    dot = norm.rfind(".")
    if dot == -1:
        return None
    return _EXT_LANGUAGE.get(norm[dot:])


def source_parses(source: str, *, language: str = "python") -> bool | None:
    """Whether ``source`` parses for ``language``.

    Returns True/False for Python (stdlib :mod:`ast`), and None (unknown) for
    the tree-sitter languages: their parsers are error-tolerant, so an empty
    symbol list cannot be distinguished from a parse failure.
    """
    if language == "python":
        try:
            ast.parse(source)
            return True
        except (SyntaxError, ValueError):
            return False
    return None


def extract_symbols(source: str, *, language: str = "python") -> list[AstSymbol]:
    """Recover the symbol spans declared in ``source``.

    Returns an empty list for unsupported languages, a missing tree-sitter grammar, or source
    that cannot be parsed (e.g. mid-edit syntax errors), so callers can safely fall back.
    """
    if language == "python":
        return _extract_python_symbols(source)
    if language in ("javascript", "java", "css"):
        return _extract_treesitter_symbols(source, language)
    return []


def _extract_python_symbols(source: str) -> list[AstSymbol]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    symbols: list[AstSymbol] = []

    def visit(node: ast.AST, prefix: tuple[str, ...], inside_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                is_class = isinstance(child, ast.ClassDef)
                dotted = (*prefix, child.name)
                if is_class:
                    kind = _CLASS_LABEL
                else:
                    kind = _METHOD_LABEL if inside_class else _FUNCTION_LABEL
                start = int(getattr(child, "lineno", 0) or 0)
                end = int(getattr(child, "end_lineno", start) or start)
                symbols.append(
                    AstSymbol(
                        name=child.name,
                        dotted_suffix=".".join(dotted),
                        kind=kind,
                        start_line=start,
                        end_line=end,
                    )
                )
                visit(child, dotted, inside_class=is_class)
            else:
                # Recurse into non-symbol nodes (e.g. ``if``/``try`` blocks) so nested defs are
                # still discovered, carrying the current prefix forward.
                visit(child, prefix, inside_class)

    visit(tree, (), inside_class=False)
    return symbols


# --- tree-sitter backend (JavaScript / Java / CSS) -------------------------------------------

# Per-language node-type classification. ``classes`` map a class-like node type to its label and
# open a "class scope" (so functions directly inside become Methods). ``funcs`` are
# function/method node types.
_TS_CONFIG = {
    "javascript": {
        "grammar": "tree_sitter_javascript",
        "classes": {"class_declaration": _CLASS_LABEL, "class_expression": _CLASS_LABEL},
        "funcs": {
            "function_declaration",
            "generator_function_declaration",
            "function_expression",
            "method_definition",
        },
    },
    "java": {
        "grammar": "tree_sitter_java",
        "classes": {
            "class_declaration": _CLASS_LABEL,
            "interface_declaration": _INTERFACE_LABEL,
            "enum_declaration": _ENUM_LABEL,
            "record_declaration": _CLASS_LABEL,
            "annotation_type_declaration": _INTERFACE_LABEL,
        },
        "funcs": {"method_declaration", "constructor_declaration", "compact_constructor_declaration"},
    },
}


@lru_cache(maxsize=None)
def _ts_parser(language: str):
    """Build (and cache) a tree-sitter parser for ``language``, or None if unavailable."""
    grammar = {
        "javascript": "tree_sitter_javascript",
        "java": "tree_sitter_java",
        "css": "tree_sitter_css",
    }.get(language)
    if grammar is None:
        return None
    try:
        import importlib

        from tree_sitter import Language, Parser

        mod = importlib.import_module(grammar)
        return Parser(Language(mod.language()))
    except Exception:
        return None


def treesitter_available(language: str) -> bool:
    """True when a tree-sitter parser for ``language`` can be loaded."""
    return _ts_parser(language) is not None


def _ts_node_name(node) -> str | None:
    """Best-effort symbol name: the ``name`` field, else the first identifier-ish child."""
    named = node.child_by_field_name("name")
    if named is not None:
        return named.text.decode("utf-8", "replace")
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "type_identifier"):
            return child.text.decode("utf-8", "replace")
    return None


def _extract_treesitter_symbols(source: str, language: str) -> list[AstSymbol]:
    parser = _ts_parser(language)
    if parser is None:
        return []
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:
        return []
    if language == "css":
        return _extract_css_symbols(tree.root_node)
    return _extract_code_symbols(tree.root_node, _TS_CONFIG[language])


def _extract_code_symbols(root, config: dict) -> list[AstSymbol]:
    """Walk a JS/Java tree, emitting class/interface/enum and function/method spans."""
    classes: dict[str, str] = config["classes"]
    funcs: set[str] = config["funcs"]
    symbols: list[AstSymbol] = []

    def emit(name: str, dotted: tuple[str, ...], kind: str, node) -> None:
        symbols.append(
            AstSymbol(
                name=name,
                dotted_suffix=".".join(dotted),
                kind=kind,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
            )
        )

    def visit(node, prefix: tuple[str, ...], in_class: bool) -> None:
        for child in node.children:
            t = child.type
            if t in classes:
                name = _ts_node_name(child) or "<anonymous>"
                dotted = (*prefix, name)
                emit(name, dotted, classes[t], child)
                visit(child, dotted, in_class=True)
            elif t in funcs:
                name = _ts_node_name(child)
                if name is None:
                    visit(child, prefix, in_class)
                    continue
                dotted = (*prefix, name)
                emit(name, dotted, _METHOD_LABEL if in_class else _FUNCTION_LABEL, child)
                # Inside a function body we are no longer directly in a class scope.
                visit(child, dotted, in_class=False)
            elif t == "variable_declarator":
                # JS: `const foo = () => {}` / `const foo = function () {}`.
                value = child.child_by_field_name("value")
                if value is not None and value.type in ("arrow_function", "function_expression"):
                    name = _ts_node_name(child)
                    if name is not None:
                        dotted = (*prefix, name)
                        emit(name, dotted, _METHOD_LABEL if in_class else _FUNCTION_LABEL, child)
                        visit(value, dotted, in_class=False)
                        continue
                visit(child, prefix, in_class)
            else:
                visit(child, prefix, in_class)

    visit(root, (), in_class=False)
    return symbols


def _extract_css_symbols(root) -> list[AstSymbol]:
    """Walk a CSS tree, emitting one symbol per rule set (by selector) and @keyframes (by name).

    CSS has no nesting of named symbols, so the selector text (whitespace-collapsed) is used as
    both the name and the dotted suffix. At-rules like ``@media`` are descended into so the rule
    sets they contain are still captured.
    """
    symbols: list[AstSymbol] = []

    def emit(name: str, kind: str, node) -> None:
        name = " ".join(name.split())
        if not name:
            return
        symbols.append(
            AstSymbol(
                name=name,
                dotted_suffix=name,
                kind=kind,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
            )
        )

    def visit(node) -> None:
        for child in node.children:
            t = child.type
            if t == "rule_set":
                selectors = next((c for c in child.children if c.type == "selectors"), None)
                name = selectors.text.decode("utf-8", "replace") if selectors else ""
                emit(name, _RULE_LABEL, child)
                # Do not descend: declarations inside a rule are not symbols.
            elif t == "keyframes_statement":
                kn = next((c for c in child.children if c.type == "keyframes_name"), None)
                emit(kn.text.decode("utf-8", "replace") if kn else "", _KEYFRAMES_LABEL, child)
            elif t in ("media_statement", "supports_statement", "at_rule"):
                visit(child)  # capture rule sets nested inside the at-rule block
            else:
                visit(child)

    visit(root)
    return symbols


def symbols_for_range(
    symbols: list[AstSymbol],
    lo: int,
    hi: int,
) -> list[AstSymbol]:
    """Return every most-specific symbol a changed range ``[lo, hi]`` touches.

    A single ``--unified=0`` hunk can span several sibling symbols (e.g. two new functions
    appended in one edit), so we keep **all** overlapping symbols that are *innermost* - i.e.
    that do not strictly contain another overlapping symbol. That splits a multi-symbol hunk
    per symbol while still attributing a new method to ``Class.method`` rather than the
    enclosing class (the class contains the method, so it is dropped as an outer container).

    We use *overlap* rather than full enclosure because a hunk typically includes separator
    blank lines that sit outside the new symbol's span. Returns ``[]`` when no symbol overlaps
    the range (module-level code), so the caller falls back to the file node. Results are
    ordered by ``start_line``.
    """
    if lo > hi:
        lo, hi = hi, lo

    overlapping = [s for s in symbols if s.start_line <= hi and lo <= s.end_line]
    leaves = [
        s
        for s in overlapping
        if not any(
            o is not s
            and s.start_line <= o.start_line
            and o.end_line <= s.end_line
            and s.span_size() > o.span_size()
            for o in overlapping
        )
    ]
    leaves.sort(key=lambda s: (s.start_line, s.span_size()))
    return leaves


def symbol_for_range(
    symbols: list[AstSymbol],
    lo: int,
    hi: int,
) -> AstSymbol | None:
    """The single most specific symbol for ``[lo, hi]`` (smallest innermost overlap), or None.

    Kept for callers that need one representative symbol; multi-symbol hunks should use
    :func:`symbols_for_range` so every touched symbol is attributed.
    """
    leaves = symbols_for_range(symbols, lo, hi)
    if not leaves:
        return None
    leaves.sort(key=lambda s: (s.span_size(), s.start_line))
    return leaves[0]
