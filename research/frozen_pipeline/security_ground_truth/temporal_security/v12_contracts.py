"""Source-shaped public contracts, shared by all four v12 arms."""
import ast
import re


def intrinsic_contract(source, symbol, claim):
    tree = ast.parse(source)
    leaf = symbol.rsplit('.', 1)[-1]
    nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.ClassDef, ast.FunctionDef,
             ast.AsyncFunctionDef)) and n.name == leaf]
    if len(nodes) != 1:
        return None
    node = nodes[0]
    # Label helpers must retain renderer evidence, even if their names mention
    # HTML or escaping. A class-wide hypothesis cannot bypass that constraint.
    if 'label' in leaf.lower() or any(isinstance(n, ast.FunctionDef) and
            n.name == 'label_from_instance' for n in ast.walk(node)):
        return None
    parser_classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)
                      and any(ast.unparse(b).split('.')[-1] == 'HTMLParser' for b in n.bases)}
    parser_scopes=set(parser_classes)
    # Public wrappers may delegate through a private sanitizer. Follow local
    # syntax conservatively without relying on a benchmark-specific name.
    for _ in range(4):
        for candidate in ast.walk(tree):
            if isinstance(candidate,(ast.FunctionDef,ast.AsyncFunctionDef)):
                called={ast.unparse(n.func).split('.')[-1] for n in ast.walk(candidate) if isinstance(n,ast.Call)}
                if called & parser_scopes:parser_scopes.add(candidate.name)
    calls = {ast.unparse(n.func).split('.')[-1] for n in ast.walk(node) if isinstance(n, ast.Call)}
    parser = (isinstance(node, ast.ClassDef) and node.name in parser_classes) or bool(calls & parser_scopes)
    if parser and re.search(r'entit|char.?ref|strip.{0,15}tag|tag.{0,15}strip|sanitiz', claim, re.I):
        return 'public_parser_entity_and_tag_representation_contract'
    # Form option construction is a distinct API boundary from a choice-label
    # producer. Require the actual options mapping and model-field assignment.
    keys = set()
    help_assignment = False
    for assignment in ast.walk(node):
        if not isinstance(assignment, ast.Assign):
            continue
        for target in assignment.targets:
            if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                keys.add(target.slice.value if isinstance(target.slice.value, str) else '')
                if (target.slice.value == 'help_text' and isinstance(assignment.value, ast.Attribute)
                        and assignment.value.attr == 'help_text'):
                    help_assignment = True
    if (help_assignment and {'label', 'required'} <= keys
            and re.search(r'help.?text', claim, re.I)):
        return 'form_field_help_text_option_contract'
    return None
