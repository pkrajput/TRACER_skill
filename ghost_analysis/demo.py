"""Create a fully synthetic mini-SWE-style archive; never execute its contents."""
import json
from pathlib import Path
import zipfile

from .structure import sha


def build_demo(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('examples')
    names = ['writer.py', 'noop.py', 'data.py', 'before.py', 'after.py', 'final.py']
    content = {name: source.joinpath(name).read_text() for name in names}
    (out / 'source').mkdir()
    for name, text in content.items():
        (out / 'source' / name).write_text(text)
    files = {name: sha(content[name]) for name in ['writer.py', 'noop.py', 'data.py']}
    snapshots = [
        dict(snapshot_id='initial', files={'product.py': sha(content['before.py'])}, tmp_files={}),
        dict(snapshot_id='created', files={**files, 'product.py': sha(content['before.py'])}, tmp_files={}),
        dict(snapshot_id='written', files={**files, 'product.py': sha(content['after.py'])}, tmp_files={}),
        dict(snapshot_id='final', files={**files, 'product.py': sha(content['final.py'])}, tmp_files={}),
    ]
    events = [
        dict(event_id='create', sequence=1, command='echo synthetic_creation', before_snapshot='initial', after_snapshot='created'),
        dict(event_id='write', sequence=2, command='python writer.py', exit_code=0, before_snapshot='created', after_snapshot='written'),
        dict(event_id='revise', sequence=3, command='echo synthetic_later_revision', before_snapshot='written', after_snapshot='final'),
        dict(event_id='noop', sequence=4, command='python noop.py', exit_code=0, before_snapshot='final', after_snapshot='final'),
    ]
    def lines(rows):
        return ''.join(json.dumps(row) + '\n' for row in rows)
    batch = out / 'batch'
    inputs = batch / 'inputs/swebench/synthetic-demo'
    inputs.mkdir(parents=True)
    (batch / 'endpoint_census_final.jsonl').write_text(lines([
        dict(run_id='synthetic-demo', benchmark='swebench', eligible=True, synthetic=True)]))
    (batch / 'file_inventory.jsonl').write_text(lines([
        dict(run_id='synthetic-demo', task='synthetic-task', path=name,
             final_content_sha256=digest, stratum='repository') for name, digest in files.items()]))
    for name, value in [('initial', snapshots[0]), ('final', snapshots[-1]),
                        ('instance', dict(repo='synthetic/example', base_commit='synthetic-base'))]:
        (inputs / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
    with zipfile.ZipFile(out / 'trajectory.zip', 'w') as archive:
        for text in set(content.values()):
            archive.writestr('ghost_model_families/blobs/' + sha(text), text)
        archive.writestr('ghost_model_families/runs/synthetic-demo/events.jsonl', lines(events))
        archive.writestr('ghost_model_families/runs/synthetic-demo/snapshots.jsonl', lines(snapshots))
