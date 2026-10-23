"""Fast delta-only Python lexical-name validation and honest coverage warnings."""
import ast
import builtins
from collections import Counter
import difflib
import symtable


def undefined_names(source, path='<candidate>'):
    tree=ast.parse(source,filename=path);table=symtable.symtable(source,path,'exec')
    globals_={s.get_name() for s in table.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    globals_.update(vars(builtins));globals_.update({'__name__','__file__','__package__','__doc__','__spec__','__loader__','__builtins__','__annotations__'})
    # Star imports and dynamic globals prevent a definite module-level claim.
    star=any(isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names) for n in tree.body)
    rows=[]
    def walk(scope, parents=()):
        name='.'.join((*parents,scope.get_name()))
        for s in scope.get_symbols():
            missing=s.is_referenced() and s.is_global() and s.get_name() not in globals_
            if missing and not star:
                lines=[n.lineno for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load) and n.id==s.get_name() and n.lineno>=scope.get_lineno()]
                rows.append({'name':s.get_name(),'scope':name,'line':min(lines) if lines else scope.get_lineno()})
        for child in scope.get_children():walk(child,(*parents,scope.get_name()))
    walk(table)
    return rows


def validate_edit(before, after, path):
    """Do not block a legitimate patch for an unrelated existing lint failure."""
    previous={(r['scope'],r['name']) for r in undefined_names(before,path)}
    introduced=[r for r in undefined_names(after,path) if (r['scope'],r['name']) not in previous]
    if introduced:
        raise ValueError('Edit introduces undefined Python names: '+', '.join(f"{r['name']} at {path}:{r['line']} ({r['scope']})" for r in introduced))
    return {'status':'no_new_definite_undefined_names','scope':'lexical Python globals; not type checking, runtime import validation or proof of branch safety'}


def changed_lines(before, after):
    lines=set();new=after.splitlines()
    for tag,i,j,a,b in difflib.SequenceMatcher(a=before.splitlines(),b=new,autojunk=False).get_opcodes():
        if tag!='equal':lines.update(range(a+1,b+1) if b>a else [max(1,min(len(new),a+1))])
    return sorted(lines)


def coverage_warnings(editor, checks, patch_hash):
    result=[]
    for path,source in editor.edits.items():
        if source==editor.original[path]:continue
        changed=changed_lines(editor.original[path],source);covered=set()
        for c in checks:
            if c.get('candidate_patch_sha256')==patch_hash:
                covered.update(c.get('feedback',{}).get('edited_file_executed_lines',{}).get(path,[]))
        missing=sorted(set(changed)-covered)
        if missing:result.append({'path':path,'edited_lines_without_recorded_execution':missing,
            'warning':'Edited lines/branches lack recorded execution on this exact candidate. Functional pass alone does not establish their coverage.',
            'functional_line_coverage':'not_instrumented','scope':'Python line events; not branch/path coverage'})
    return result
