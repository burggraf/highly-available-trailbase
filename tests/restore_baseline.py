#!/usr/bin/env python3
"""D1 finite S3 restore oracle. Uses new isolated files; never touches a live depot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'hat'))
from demo_smoke import request, verify_restore
from transition import logical_signature


def restore(root, config, positions, ledger, support, binaries):
    os.umask(0o077)
    selected = json.loads(positions.read_text())
    assert set(selected) == {'main', 'session', 'aux'}
    assert all(type(v) is int and 0 < v < 2**64 for v in selected.values())
    work = root / uuid.uuid4().hex
    work.mkdir(mode=0o700)
    depot = work / 'depot'
    shutil.copytree(support, depot)
    data = depot / 'data'
    data.mkdir()
    evidence = {'positions': selected, 'databases': {}}
    for name, position in selected.items():
        target = data / (name + '.db')
        with (work / (name + '-restore.log')).open('xb') as log:
            subprocess.run([str(binaries/'litestream'), 'restore', '-config', str(config), '-txid', f'{position:016x}',
                            '-o', str(target), '/var/lib/hat-demo/depot/data/' + name + '.db'],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        assert target.is_file() and not target.is_symlink()
        with sqlite3.connect(f'file:{target}?mode=ro', uri=True) as db:
            # TrailBase custom CHECK functions are not in stock Python SQLite.
            db.execute('PRAGMA ignore_check_constraints=ON')
            assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert not db.execute('PRAGMA foreign_key_check').fetchall()
            if name in ('main','aux'):
                assert db.execute('SELECT count(*) FROM hat_ops').fetchone()[0] > 0
        evidence['databases'][name] = {'integrity':'ok', 'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    evidence['signature'] = logical_signature(data)
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    env = {k:v for k,v in os.environ.items() if not k.startswith('IDRIVE_')}
    with (work/'trail-oracle.log').open('xb') as log:
        child = subprocess.Popen([str(binaries/'trail'), '--depot', str(depot), 'run', '--address', f'127.0.0.1:{port}', '--stderr-logging'],
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            deadline = time.monotonic()+60
            while True:
                assert child.poll() is None, 'oracle TrailBase exited'
                try:
                    code,_=request(base,'/api/healthcheck')
                    if code==200:break
                except OSError:pass
                assert time.monotonic()<deadline, 'oracle readiness timeout'
                time.sleep(.2)
            verify_restore(base, ledger)
            evidence['auth_and_records'] = 'PASS'
        finally:
            child.terminate()
            try:child.wait(timeout=15)
            except subprocess.TimeoutExpired:child.kill();child.wait()
    (work/'result.json').write_text(json.dumps(evidence,indent=2))
    print('PASS: independent finite three-DB restore, integrity and HTTP/auth oracle; isolated oracle stopped')
    return dict(work=str(work), **evidence)

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','config','positions','ledger','support','binaries'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--result', type=Path)
    a=p.parse_args(); result=restore(a.root,a.config,a.positions,a.ledger,a.support,a.binaries)
    if a.result:
        with a.result.open('x') as f: json.dump(result,f,indent=2)
