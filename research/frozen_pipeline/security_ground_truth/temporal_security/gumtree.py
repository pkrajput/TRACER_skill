"""Deterministic Python AST edit hints backed by the actual GumTree matcher.

This is syntax evidence, not a proof of flow, developer intent, or vulnerability.
The Python frontend replaces the Java/Spoon frontend used by CoLeFunDa.
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
import hashlib
import functools
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from .gumtree_install import BRIDGE, DEFAULT_HOME, VERSION

SCHEMA = "python-gumtree-temporal-v1"


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _short(value: Any, limit: int = 100) -> str:
    text = str(value).replace("\n", "\\n").replace("\r", "\\r")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _ast_tree(source: str, path: str, *, max_nodes: int = 50000) -> tuple[dict, dict]:
    parsed = ast.parse(source, filename=path)
    records = {}
    source_lines = source.splitlines()

    def walk(node, scope="<module>", parent="<root>", field="", line=0):
        if len(records) >= max_nodes:
            raise ValueError("AST exceeds node limit")
        ident = len(records)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = node.name if scope == "<module>" else scope + "." + node.name
        kind = type(node).__name__
        line = getattr(node, "lineno", line)
        scalars = {key: value for key, value in ast.iter_fields(node)
                   if not isinstance(value, (ast.AST, list)) and value is not None}
        # Constants may be bytes/complex/Ellipsis: repr preserves their syntax category.
        label = json.dumps(scalars, ensure_ascii=False, sort_keys=True, default=repr)
        label = "" if label == "{}" else label
        rec = {"id": ident, "type": kind, "label": label, "scope": scope,
               "line": line, "end_line": getattr(node, "end_lineno", line),
               "parent_type": parent, "field": field}
        if 0 < line <= len(source_lines) and kind in {"If", "Call", "Return", "Raise", "Expr", "Assign", "Assert", "With", "Try"}:
            rec["source_excerpt"] = _short(source_lines[line - 1].strip(), 160)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.Expr)):
            calls, guards = [], []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    calls.append(_short(ast.unparse(child.func), 100))
                elif isinstance(child, (ast.If, ast.Assert)):
                    guards.append(_short(ast.unparse(child.test), 160))
            calls, guards = list(dict.fromkeys(calls)), list(dict.fromkeys(guards))
            rec["subtree_syntax"] = {"calls": calls[:10], "guards": guards[:6],
                                      "omitted_calls": max(0, len(calls) - 10),
                                      "omitted_guards": max(0, len(guards) - 6)}
        if isinstance(node, ast.ExceptHandler):
            rec['fallback_syntax'] = _short(ast.unparse(node), 220)
        elif isinstance(node, ast.IfExp):
            rec['fallback_syntax'] = _short(ast.unparse(node), 220)
        records[ident] = rec
        children = []
        for key, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                children.append(walk(value, scope, kind, key, line))
            elif isinstance(value, list):
                # Preserve scalar lists such as Global.names and ImportFrom.names.
                for child in value:
                    if isinstance(child, ast.AST):
                        children.append(walk(child, scope, kind, key, line))
                    else:
                        child_id = len(records)
                        leaf = {"id": child_id, "type": "Scalar_" + key,
                                "label": repr(child), "children": []}
                        records[child_id] = {**{k: v for k, v in leaf.items() if k != "children"},
                                             "scope": scope, "line": line, "end_line": line,
                                             "parent_type": kind, "field": key}
                        children.append(leaf)
        # Field role is in the type, so moving a call from a condition into its body
        # cannot silently be treated as the same syntactic position.
        return {"id": ident, "type": kind + (":" + field if field else ""),
                "label": label, "children": children}

    return walk(parsed), records


@functools.lru_cache(maxsize=4)
def _verify_installation(home: Path, manifest_digest: str) -> dict:
    manifest = json.loads((home / "manifest.json").read_text())
    lock = json.loads(Path(__file__).with_name("gumtree_dependencies.json").read_text())
    if manifest["artifacts"] != lock["artifacts"] or manifest["version"] != lock["version"]:
        raise RuntimeError("GumTree installation differs from pinned dependencies")
    for entry in lock["artifacts"]:
        if digest((home / "lib" / entry["filename"]).read_bytes()) != entry["sha256"]:
            raise RuntimeError("GumTree dependency hash mismatch: " + entry["filename"])
    if manifest["bridge_source_sha256"] != digest(BRIDGE):
        raise RuntimeError("GumTree bridge needs recompiling")
    if digest((home / "TracerGumtree.class").read_bytes()) != manifest["bridge_class_sha256"]:
        raise RuntimeError("GumTree bridge class differs from installation manifest")
    return manifest


def matcher_provenance(home: Path | None = None) -> dict:
    home = Path(home or os.environ.get("TRACER_GUMTREE_HOME", DEFAULT_HOME))
    manifest_file = home / "manifest.json"
    if not manifest_file.exists():
        raise RuntimeError("GumTree is not installed; run python3 -m security_ground_truth.temporal_security.gumtree_install")
    manifest_digest = digest(manifest_file.read_bytes())
    manifest = _verify_installation(home, manifest_digest)
    return {"name": "GumTree ClassicGumtree", "version": VERSION,
            "edit_script": "SimplifiedChawatheScriptGenerator", "frontend": "Python stdlib ast",
            "manifest_sha256": manifest_digest,
            "bridge_source_sha256": manifest["bridge_source_sha256"],
            "frontend_sha256": digest(Path(__file__).read_bytes())}


def summarize_pair(before: str, after: str, path: str, event_id: str, *,
                   symbol: str | None = None, max_operations: int = 24,
                   max_symbols: int = 12, home: Path | None = None,
                   timeout: int = 30) -> dict:
    """Produce bounded, provenance-bearing edit hints from two observed sources.

    A symbol filters actual edit locations; it never creates synthetic history.
    Prefix matches include nested symbols. Missing/invalid sources are explicit.
    This function does not access a repository, task metadata, or evaluator files.
    """
    result = {"schema": SCHEMA, "path": path, "event_id": event_id,
              "before_sha256": digest(before), "after_sha256": digest(after),
              "evidence_kind": "syntactic_ast_edit_operations", "semantic_flow_proven": False,
              "symbol_filter": symbol, "operations": [], "symbol_hints": []}
    if max_operations < 0 or max_symbols < 0:
        raise ValueError("Limits must be nonnegative")
    try:
        before_tree, old = _ast_tree(before, path)
        after_tree, new = _ast_tree(after, path)
    except (SyntaxError, ValueError, RecursionError) as error:
        return {**result, "status": "unparseable_or_oversized", "error": _short(error, 300)}
    if before == after:
        return {**result, "status": "unchanged", "raw_operation_count": 0,
                "relevant_operation_count": 0, "truncated": False}
    home = Path(home or os.environ.get("TRACER_GUMTREE_HOME", DEFAULT_HOME))
    result["matcher"] = matcher_provenance(home)
    payload = json.dumps({"before": before_tree, "after": after_tree}, ensure_ascii=False).encode()
    try:
        run = subprocess.run(["java", "-Xmx512m", "-cp", str(home) + os.pathsep + str(home / "lib/*"),
                              "TracerGumtree"], input=payload, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {**result, "status": "matcher_timeout"}
    if run.returncode:
        return {**result, "status": "matcher_error", "error": run.stderr.decode(errors="replace")[-1500:]}
    data = json.loads(run.stdout)
    operations = []
    for action in data["actions"]:
        a, b = old.get(action.get("source_id")), new.get(action.get("target_id"))
        anchor = b or a
        if anchor is None:
            raise ValueError("GumTree returned a node outside the supplied trees")
        scopes = {x["scope"] for x in (a, b) if x}
        covered = None
        if symbol is not None and not any(s == symbol or s.startswith(symbol + ".") for s in scopes):
            # SimplifiedChawathe may insert/delete/move an entire class as one
            # tree action. Its methods are part of that *observed* subtree;
            # requiring the action's root scope to equal the method drops them.
            # Preserve the actual parent action, never invent a method action.
            if action['operation'] in {'insert-tree','delete-tree','move-tree'}:
                for parent,records in [(b,new),(a,old)]:
                    if not parent or not symbol.startswith(parent['scope']+'.'):continue
                    covered=next((r for r in records.values() if r['scope']==symbol
                        and r['type'] in {'FunctionDef','AsyncFunctionDef','ClassDef'}
                        and parent['line']<=r['line']<=r['end_line']<=parent['end_line']),None)
                    if covered:break
            if covered is None:continue
        operation = action["operation"].split("-")[0]
        entry = {"operation": operation, "gumtree_action": action["operation"],
                 "node_type": anchor["type"], "symbol": anchor["scope"],
                 "before": a, "after": b, "event_id": event_id}
        old_text, new_text = _short((a or {}).get("label", "")), _short((b or {}).get("label", ""))
        if not old_text and a:
            old_text = a.get("source_excerpt", "")
        if not new_text and b:
            new_text = b.get("source_excerpt", "")
        change = f" {old_text} → {new_text}" if operation == "update" else " " + (new_text or old_text)
        entry["hint"] = (f"{operation.capitalize()} {anchor['type']}{change} at "
                         f"{anchor['parent_type']}.{anchor['field']} in {anchor['scope']}").strip()
        if operation == "move" and a and b:
            entry["hint"] += f" (line {a['line']} → {b['line']})"
        if covered:
            entry['covered_target_symbol']=symbol
            entry['hint']+='; recorded subtree contains target '+symbol
        syntax=(covered or anchor).get('subtree_syntax')
        if operation in {"insert", "delete", "move"} and syntax:
            if syntax["calls"]:
                entry["hint"] += "; calls " + ", ".join(syntax["calls"][:5])
            if syntax["guards"]:
                entry["hint"] += "; guards " + ", ".join(syntax["guards"][:3])
        operations.append(entry)
    grouped = defaultdict(list)
    for operation in operations:
        grouped[operation["symbol"]].append(operation)
    hints = []
    for name, edits in sorted(grouped.items()):
        shown = edits[:6]
        hints.append({"symbol": name, "hint": "; ".join(e["hint"] for e in shown),
                      "operation_counts": dict(Counter(e["operation"] for e in edits)),
                      "covered_target_symbols":sorted({e['covered_target_symbol'] for e in edits if e.get('covered_target_symbol')}),
                      "operations_omitted": len(edits) - len(shown), "event_id": event_id})
    result.update(status="ok", operations=operations[:max_operations], symbol_hints=hints[:max_symbols],
                  raw_operation_count=len(data["actions"]), relevant_operation_count=len(operations),
                  mapped_node_count=len(data["mappings"]),
                  truncated=len(operations) > max_operations or len(hints) > max_symbols)
    # Compare only observed ASTs. These are net guard changes; discontinuous
    # trajectory fragments do not establish when/why an intermediate edit ran.
    def observed_guards(records):
        values={}
        for rec in records.values():
            if symbol and rec['scope']!=symbol:continue
            if rec['type'] not in {'If','Assert','While'}:continue
            tests=rec.get('subtree_syntax',{}).get('guards',[])[:1]
            if not tests and rec.get('source_excerpt'):tests=[rec['source_excerpt']]
            for guard in tests:values[(rec['scope'],guard)]=rec['line']
        return values
    old_guards,new_guards=observed_guards(old),observed_guards(new)
    added=sorted(set(new_guards)-set(old_guards));removed=sorted(set(old_guards)-set(new_guards))
    result['guard_deltas']={'basis':'net_AST_difference_between_recorded_sources',
        'added':[{'symbol':s,'condition':g,'line':new_guards[(s,g)]} for s,g in added[:3]],
        'removed':[{'symbol':s,'condition':g,'line':old_guards[(s,g)]} for s,g in removed[:3]],
        'omitted_added':max(0,len(added)-3),'omitted_removed':max(0,len(removed)-3)}
    def observed_fallbacks(records):
        return {(r['scope'],r['type'],r['fallback_syntax']):r['line'] for r in records.values()
                if 'fallback_syntax' in r and (not symbol or r['scope']==symbol)}
    old_fallbacks,new_fallbacks=observed_fallbacks(old),observed_fallbacks(new)
    added=sorted(set(new_fallbacks)-set(old_fallbacks));removed=sorted(set(old_fallbacks)-set(new_fallbacks))
    result['fallback_deltas']={'basis':'observed_exception_or_conditional_fallback_syntax; intent_not_inferred',
        'added':[{'symbol':s,'kind':k,'syntax':v,'line':new_fallbacks[(s,k,v)]} for s,k,v in added[:2]],
        'removed':[{'symbol':s,'kind':k,'syntax':v,'line':old_fallbacks[(s,k,v)]} for s,k,v in removed[:2]],
        'omitted_added':max(0,len(added)-2),'omitted_removed':max(0,len(removed)-2)}
    return result
