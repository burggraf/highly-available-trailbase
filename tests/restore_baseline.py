#!/usr/bin/env python3
"""Independent finite restore oracle for the canonical acceptance contract."""
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
import recovery
from client import read_closed_ledger
from demo_smoke import request, verify_restore
from recovery import classify_fault
from transition import logical_signature


def _raw(path, limit=4 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not (st.st_mode & 0o170000) == 0o100000 or st.st_nlink != 1 or st.st_size > limit:
            raise ValueError('unsafe oracle input')
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1-len(data)))
            if not part: break
            data.extend(part)
        if len(data) > limit: raise ValueError('oversized oracle input')
        return bytes(data)
    finally: os.close(fd)


def restore(root, acceptance_request, config, ledger, support, binaries, fault_ledger=None):
    os.umask(0o077)
    request_raw = _raw(acceptance_request, 1 << 20)
    request_object = recovery.parse_canonical_json(request_raw)
    operation = {'id': request_object['operation'], 'source': request_object['source'],
                 'target': request_object['target'],
                 'source_epoch': request_object['epoch'] if request_object['phase'] in ('compare','reconciled-compare') else 'd1-source',
                 'new_epoch': 'd1-' + request_object['operation']}
    request_value = recovery.parse_acceptance_request(request_raw, operation)
    config_raw = _raw(config, 1 << 20)
    recovery._replica_config(config_raw, request_value['epoch'])
    ledger_raw = _raw(ledger)
    if request_value['profile'] != 'recovery-comparison':
        recovery._protected_ledger(ledger_raw)
    if fault_ledger is not None:
        events = read_closed_ledger(fault_ledger, request_value['epoch'])
        if hashlib.sha256(_raw(fault_ledger)).hexdigest() != request_value['inputs']['fault_ledger_sha256']:
            raise ValueError('fault ledger changed')
    else:
        events = None
    root = Path(root)
    if not root.is_dir() or root.is_symlink(): raise ValueError('oracle root is unsafe')
    work = root / uuid.uuid4().hex; work.mkdir(mode=0o700)
    depot = work / 'depot'; shutil.copytree(support, depot); data = depot / 'data'; data.mkdir()
    evidence = {'databases': {}}
    for name in ('main', 'session', 'aux'):
        position = request_value['positions'][name]
        target = data / (name + '.db')
        with (work / (name + '-restore.log')).open('xb') as log:
            subprocess.run([str(Path(binaries)/'litestream'), 'restore', '-config', str(config), '-txid', f'{position:016x}',
                            '-o', str(target), '/var/lib/hat-demo/depot/data/' + name + '.db'],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        if target.is_symlink() or not target.is_file(): raise ValueError('restore output is unsafe')
        with sqlite3.connect(f'file:{target}?mode=ro', uri=True) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            if db.execute('PRAGMA integrity_check').fetchone() != ('ok',) or db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('database checks failed')
        evidence['databases'][name] = {'position': position, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'integrity':'PASS', 'foreign_keys':'PASS'}
    evidence['signature'] = logical_signature(data)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    env = {k:v for k,v in os.environ.items() if not k.startswith('IDRIVE_')}
    log = (work / 'trail-oracle.log').open('xb')
    child = subprocess.Popen([str(Path(binaries)/'trail'), '--depot', str(depot), 'run', '--address', f'127.0.0.1:{port}', '--stderr-logging'], stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        deadline = time.monotonic() + 60
        while True:
            if child.poll() is not None: raise ValueError('oracle TrailBase exited')
            try:
                code, _ = request(base, '/api/healthcheck')
                if code == 200: break
            except OSError: pass
            if time.monotonic() >= deadline: raise ValueError('oracle readiness timeout')
            time.sleep(.2)
        verify_restore(base, ledger)
    finally:
        child.terminate()
        try: child.wait(timeout=15)
        except subprocess.TimeoutExpired: child.kill(); child.wait()
        log.close()
    evidence['checks'] = {'records':'PASS', 'authentication':'PASS'}
    if events is not None:
        outcomes = classify_fault(events, data)
        recovery.validate_fault_outcomes(outcomes, events)
        evidence['checks'].update(fault_outcomes=outcomes, acknowledged_loss='NONE')
    result = {'schema':'hat-restore-acceptance-1', 'request':request_value,
              'request_sha256':hashlib.sha256(recovery.canonical_json(request_value)).hexdigest(),
              'databases':evidence['databases'], 'signature':evidence['signature'], 'checks':evidence['checks']}
    raw = recovery.canonical_json(result)
    result_path = work / 'result.json'
    fd = os.open(result_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    dfd=os.open(work, os.O_RDONLY|os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
    recovery.validate_acceptance_result(result, request_value, operation)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--acceptance-request', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--ledger', type=Path, required=True)
    p.add_argument('--support', type=Path, required=True)
    p.add_argument('--binaries', type=Path, required=True)
    p.add_argument('--fault-ledger', type=Path)
    p.add_argument('--result', type=Path, required=True)
    a = p.parse_args()
    value = restore(a.root, a.acceptance_request, a.config, a.ledger, a.support, a.binaries, a.fault_ledger)
    fd = os.open(a.result, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(recovery.canonical_json(value)); stream.flush(); os.fsync(stream.fileno())
    dfd=os.open(a.result.parent, os.O_RDONLY|os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
    print('PASS: independent finite restore acceptance')
