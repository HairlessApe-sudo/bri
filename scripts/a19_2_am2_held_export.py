#!/usr/bin/env python3
"""Freeze a fresh held reproduction export and prove correspondence before and after execution."""
from hashlib import sha256
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
from tempfile import mkdtemp

TREE = '064b6b489733f5f81e8e4a0803bdc71d3d44f785'
ARCHIVE = '3bb12ee5453fe17e41d9253875f3d7d72fcc70e256b7e07752de35c8a7b9e6a4'
DRIVERS = ('scripts/a19_2_am2_fault.py', 'scripts/a19_2_am2_held.py')


def files(root):
    return {p.relative_to(root).as_posix(): (sha256(p.read_bytes()).hexdigest(), bool(p.stat().st_mode & 0o100))
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def inventory(tar):
    return {member.name: (sha256(tar.extractfile(member).read()).hexdigest(), bool(member.mode & 0o100))
            for member in tar.getmembers() if member.isfile()}


def main():
    os.umask(0o077)
    home = Path.home()
    repo = Path(__file__).resolve().parents[1]
    scratch = home / '.hermes/cache/scratch'
    evidence = home / '.hermes/evidence/BRI/A19.2'
    archive = evidence / 'am1/qualification.8sPqw2Gj/candidate.tar'
    assert sha256(archive.read_bytes()).hexdigest() == ARCHIVE
    records = evidence / 'am2/held-reproduction'
    records.mkdir(mode=0o700, exist_ok=True)
    assert records.resolve() == records and records.stat().st_mode & 0o077 == 0
    out = Path(mkdtemp(prefix='held-', dir=records))
    node = home / '.hermes/tools/node-26.12.1-linux-x64/bin/node'
    pg = scratch / 'bri16.2.DGQrGAFq/pgserver/pginstall/bin'
    chrome = home / '.hermes/tools/chromium-1248/chrome-linux64/chrome'
    swc = home / '.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz'
    deps = Path((archive.parent / 'export.path').read_text().strip()) / 'web/node_modules'
    env = dict(HOME=str(home), PATH=f'{node.parent}:/usr/bin:/bin', TMPDIR=str(scratch))
    status = 1
    export = Path(mkdtemp(prefix='a19-2-am2-held-export-', dir=scratch))
    try:
        with subprocess.Popen(['git', 'archive', '--format=tar', TREE], cwd=repo, stdout=subprocess.PIPE) as git:
            with tarfile.open(fileobj=git.stdout, mode='r|') as canonical:
                git_files = {}
                for member in canonical:
                    if member.isfile():
                        git_files[member.name] = (sha256(canonical.extractfile(member).read()).hexdigest(), bool(member.mode & 0o100))
                    else:
                        assert member.isdir(), 'Unexpected git archive member type'
            assert git.wait() == 0
        with tarfile.open(archive) as held:
            assert all(p.isfile() or p.isdir() for p in held.getmembers())
            assert inventory(held) == git_files
            held.extractall(export, filter='data')
        original = files(export)
        assert original == git_files
        assert not set(DRIVERS).intersection(original)
        for driver in DRIVERS:
            shutil.copy2(repo / driver, export / driver)
        (export / '.venv').symlink_to(repo / '.venv', target_is_directory=True)
        (export / 'web/node_modules').symlink_to(deps, target_is_directory=True)
        overlaid = files(export)
        assert set(overlaid).difference(original) == set(DRIVERS)
        assert {key: overlaid[key] for key in original} == original
        (out / 'correspondence').write_text(f'tree {TREE}\narchive {ARCHIVE}\n'
             f'PRE exact held files, modes and hashes: {len(original)}\n' +
             ''.join(f'OVERLAY {overlaid[key][0]}  {key}\n' for key in DRIVERS))
        command = ['./.venv/bin/python', '-B', DRIVERS[-1], '--pg-bin', str(pg), '--node', str(node),
                   '--chromium', str(chrome), '--swc-archive', str(swc)]
        (out / 'command').write_text(f'cd {shlex.quote(str(export))}\n' +
                  shlex.join(['env', '-i', *(f'{k}={v}' for k, v in env.items()), *command]) + '\n')
        with (out / 'toolchain').open('w') as log:
            for tool in [export / '.venv/bin/python', node, pg / 'postgres', chrome]:
                subprocess.run([tool, '--version'], check=True, stdout=log, env=env)
            log.write(f'SWC {swc.name}\n')
        with (out / 'output.log').open('w') as log:
            returncode = subprocess.run(command, env=env, cwd=export, stdout=log, stderr=subprocess.STDOUT).returncode
        (out / 'browser-exit').write_text(f'{returncode}\n')
        assert files(export) == overlaid, 'Held export changed during run'
        with (out / 'correspondence').open('a') as log:
            log.write('POST all held files and overlays unchanged; dependency and venv links are execution-only\n')
        status = returncode
    finally:
        (out / 'exit').write_text(f'{status}\n')
        shutil.rmtree(export)
        print(out, flush=True)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
