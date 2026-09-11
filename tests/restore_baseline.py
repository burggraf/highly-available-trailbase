#!/usr/bin/env python3
"""Independent finite restore oracle for the canonical acceptance contract."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sqlite3
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'hat'))
import descriptor
import recovery
from client import read_closed_ledger
from demo_smoke import request, verify_restore
from recovery import classify_fault
from transition import logical_signature


def _stat_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size)


def _trusted_ancestry(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('oracle input path is not absolute')
    parts = path.parts
    current = Path(parts[0])
    for part in parts[1:-1]:
        current /= part
        st = current.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError('oracle input ancestry is unsafe')


def _open_descriptor(path, flags=os.O_RDONLY):
    path = Path(path)
    if not path.is_absolute(): raise ValueError('oracle input path is not absolute')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = [part for part in path.parts if part not in ('/', '')]
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        result = os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=fd)
        return result
    finally:
        os.close(fd)


def _raw(path, limit=4 << 20, expected=None):
    expected_mode = stat.S_IMODE(expected[2]) if expected is not None else None
    with descriptor.DescriptorAuthority.open_file(
            path, trusted_root='/', trusted_uids={0, os.geteuid()},
            expected_uid=(expected[3] if expected is not None else None),
            expected_gid=(expected[4] if expected is not None else None),
            expected_mode=expected_mode, expected_nlink=1,
            expected_size=(expected[6] if expected is not None else None), limit=limit) as authority:
        if expected is None and stat.S_IMODE(authority.identity[2]) & 0o022:
            raise ValueError('unsafe oracle input')
        if expected is not None and authority.identity != expected:
            raise ValueError('oracle input identity changed')
        return authority.read(), authority.identity


def _read(path, limit=4 << 20, expected=None):
    return _raw(path, limit, expected)[0]


def _validate_fixed_files(root, names, uid, gid, modes):
    """Open the exact installed tree; callers retain returned authorities."""
    root = Path(root)
    expected_files = set(names)
    expected_dirs = {str(parent) for name in names for parent in Path(name).parents
                     if str(parent) not in ('.', '')}
    authorities = []
    directory = descriptor.DescriptorAuthority.open_directory(
        root, trusted_root='/', trusted_uids={0, os.geteuid()})
    authorities.append(directory); stack = [('', directory)]; found_files = set(); found_dirs = set()
    try:
        while stack:
            prefix, current = stack.pop()
            for entry in os.listdir(current.directory_fd):
                rel = str(Path(prefix) / entry) if prefix else entry
                if rel in expected_dirs:
                    child = descriptor.DescriptorAuthority.open_directory(
                        root / rel, trusted_root='/', trusted_uids={0, os.geteuid()})
                    authorities.append(child); found_dirs.add(rel); stack.append((rel, child))
                elif rel in expected_files:
                    found_files.add(rel)
                else:
                    raise ValueError('installed tree has unexpected entry')
        if found_files != expected_files or found_dirs != expected_dirs:
            raise ValueError('installed tree is incomplete')
        for name, digest in names.items():
            mode = modes[name] if isinstance(modes, dict) else modes
            item = descriptor.DescriptorAuthority.open_file(
                root / name, trusted_root='/', trusted_uids={0, os.geteuid()}, expected_uid=uid,
                expected_gid=gid, expected_mode=mode, expected_nlink=1,
                expected_sha256=digest, limit=128 << 20)
            authorities.append(item)
        for item in authorities: item.recheck()
        return authorities
    except BaseException:
        for item in reversed(authorities): item.close()
        raise


def restore(root, acceptance_request, config, ledger, support, binaries, fault_ledger=None):
    os.umask(0o077)
    request_raw = _read(acceptance_request, 1 << 20)
    request_object = recovery.parse_canonical_json(request_raw)
    operation = {'id': request_object['operation'], 'source': request_object['source'],
                 'target': request_object['target'],
                 'source_epoch': request_object['epoch'] if request_object['phase'] in ('compare','reconciled-compare') else 'd1-source',
                 'new_epoch': 'd1-' + request_object['operation']}
    request_value = recovery.parse_acceptance_request(request_raw, operation)
    config_raw = _read(config, 1 << 20)
    if hashlib.sha256(config_raw).hexdigest() != request_value['inputs']['replica_config_sha256']:
        raise ValueError('replica configuration changed')
    recovery._replica_config(config_raw, request_value['epoch'])
    ledger_raw = _read(ledger)
    inputs = request_value['inputs']
    if hashlib.sha256(ledger_raw).hexdigest() != inputs['ledger_sha256']:
        raise ValueError('ledger changed')
    authority = inputs['ledger_authority']
    if Path(ledger).resolve() != Path(authority['ledger']['path']).resolve():
        raise ValueError('ledger authority path differs')
    ledger_stat = Path(ledger).lstat()
    expected_stat = authority['ledger']
    actual_identity = {'device': ledger_stat.st_dev, 'inode': ledger_stat.st_ino,
                       'mode': ledger_stat.st_mode & 0o777, 'uid': ledger_stat.st_uid,
                       'gid': ledger_stat.st_gid, 'links': ledger_stat.st_nlink, 'bytes': ledger_stat.st_size,
                       'sha256': hashlib.sha256(ledger_raw).hexdigest()}
    if any(actual_identity[key] != expected_stat[key] for key in actual_identity):
        raise ValueError('ledger authority differs')
    if request_value['profile'] != 'recovery-comparison':
        recovery._protected_ledger(ledger_raw)
    if fault_ledger is not None:
        events = read_closed_ledger(fault_ledger, request_value['epoch'])
        if hashlib.sha256(_read(fault_ledger)).hexdigest() != request_value['inputs']['fault_ledger_sha256']:
            raise ValueError('fault ledger changed')
    else:
        events = None
    root = Path(root)
    if not root.is_dir() or root.is_symlink(): raise ValueError('oracle root is unsafe')
    work = root / uuid.uuid4().hex; work.mkdir(mode=0o700)
    expected_support = request_value['inputs']['support']
    support_authorities = _validate_fixed_files(support, expected_support, 0, os.getegid(), 0o640)
    expected_binaries = request_value['inputs']['binaries']
    if set(expected_binaries) != {'trail', 'litestream'}:
        raise ValueError('binary set is invalid')
    binary_root = Path(binaries)
    binary_authorities = _validate_fixed_files(binary_root, expected_binaries, 0, 0, 0o755)
    depot = Path(support); data = work / 'data'; data.mkdir(mode=0o700)
    evidence = {'databases': {}}
    for name in ('main', 'session', 'aux'):
        position = request_value['positions'][name]
        target = data / (name + '.db')
        with (work / (name + '-restore.log')).open('xb') as log:
            subprocess.run([str(Path(binaries)/'litestream'), 'restore', '-config', str(config), '-txid', f'{position:016x}',
                            '-o', str(target), '/var/lib/hat-demo/depot/data/' + name + '.db'],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        for authority in support_authorities + binary_authorities: authority.recheck()
        if target.is_symlink() or not target.is_file(): raise ValueError('restore output is unsafe')
        with sqlite3.connect(f'file:{target}?mode=ro', uri=True) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            if db.execute('PRAGMA integrity_check').fetchone() != ('ok',) or db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('database checks failed')
        restored = _read(target, 64 << 20)
        evidence['databases'][name] = {'position': position, 'sha256': hashlib.sha256(restored).hexdigest(), 'integrity':'PASS', 'foreign_keys':'PASS'}
    for authority in support_authorities + binary_authorities: authority.recheck()
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
    recovery.validate_acceptance_result(result, request_value, operation)
    raw = recovery.canonical_json(result)
    result_path = work / 'result.json'
    fd = os.open(result_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    dfd=os.open(work, os.O_RDONLY|os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
    if _read(result_path, 1 << 20) != raw:
        raise ValueError('result changed after write')
    for authority in support_authorities + binary_authorities: authority.recheck()
    for authority in reversed(support_authorities + binary_authorities): authority.close()
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
    raw = recovery.canonical_json(value)
    _trusted_ancestry(a.result)
    parent_fd = os.open(a.result.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(a.result.name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent_fd)
        if _read(a.result, 1 << 20) != raw: raise ValueError('result changed after write')
    finally:
        os.close(parent_fd)
    print('PASS: independent finite restore acceptance')
