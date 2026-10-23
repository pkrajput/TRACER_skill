"""Download and checksum-verify the published complete study artifact."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
NAME='tracer-complete-study-2026-10-23'
URL='https://zenodo.org/api/records/23591518/files/'+NAME+'.zip/content'
SHA256='32908f4aa48d125c88200d4409a37da7a477a4a8f1f67b4a8abb5803ac635b43'
SIZE=15260514

def unpack_verified(archive,destination):
    """Require the exact published bytes and an absent output directory."""
    if destination.exists():raise FileExistsError(destination)
    if archive.stat().st_size!=SIZE or hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:
        raise ValueError('Artifact checksum or size does not match the published release')
    with zipfile.ZipFile(archive) as zipped:
        for info in zipped.infolist():
            path=PurePosixPath(info.filename)
            if path.is_absolute() or '..' in path.parts or path.parts[0]!=NAME:
                raise ValueError('Invalid archive path')
            if stat.S_ISLNK(info.external_attr>>16):raise ValueError('Archive contains a symlink')
        with tempfile.TemporaryDirectory(prefix='tracer-unpack-',dir=destination.parent) as tmp:
            zipped.extractall(tmp)
            Path(tmp,NAME).rename(destination)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'local-output'/NAME)
    parser.add_argument('--archive',type=Path,help='Use a previously downloaded ZIP instead of the network')
    args=parser.parse_args()
    destination=args.out.resolve()
    if destination.exists():parser.error('Output already exists; use it or choose a fresh --out path')
    destination.parent.mkdir(parents=True,exist_ok=True)
    if args.archive:
        unpack_verified(args.archive,destination)
    else:
        with tempfile.TemporaryDirectory(prefix='tracer-download-',dir=destination.parent) as tmp:
            archive=Path(tmp)/'artifact.zip'
            with urllib.request.urlopen(URL,timeout=60) as source, archive.open('wb') as target:
                shutil.copyfileobj(source,target)
            unpack_verified(archive,destination)
    print('Verified artifact: '+str(destination))
    print('SHA-256: '+SHA256)

if __name__=='__main__':main()
