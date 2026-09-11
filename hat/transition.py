#!/usr/bin/env python3
"""Fixed root-only D2/D3 node operations, reached through a dedicated forced SSH command."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error

import node

STATE = Path('/var/lib/hat-node-control')
CONFIG = Path('/etc/hat-demo/node.json')
REPLICA = Path('/etc/hat-demo/litestream.yml')
BACKUP_ENV = Path('/etc/hat-demo/backup.env')


def validate_cut(cut):
    if not isinstance(cut, dict) or set(cut) != set(node.DBS) or any(type(v) is not int or not 0 < v < 2**64 for v in cut.values()):
        raise ValueError('invalid three-database cut')


def validate_request(r, c, boot):
    shapes = {'probe': set(), 'quiesce': set(), 'freeze': {'cut'}, 'restore': {'cut'},
              'prepare': {'new_epoch', 'signature', 'fence_digest'}, 'activate': set(), 'inspect-frozen': set(),
              'inspect-cold': set(), 'prepare-recovery': {'source_epoch'},
              'restore-recovery': {'cut', 'fence_digest'}, 'rejoin': {'new_epoch'}}
    if not isinstance(r, dict) or set(r) != {'action','operation','epoch','boot_id','payload'}:
        raise ValueError('invalid request shape')
    if (r['action'] not in shapes or not isinstance(r['operation'], str)
            or not re.fullmatch('[0-9a-f]{32}', r['operation']) or r['epoch'] != c['epoch']
            or (r['boot_id'] != boot and not (r['action'] in ('probe', 'inspect-cold') and r['boot_id'] is None))
            or not isinstance(r['payload'], dict) or set(r['payload']) != shapes[r['action']]):
        raise ValueError('invalid operation, epoch, boot or payload')
    if r['action'] in ('quiesce','activate','rejoin') and c['role'] != 'writer': raise ValueError('not a writer')
    if r['action'] in ('freeze','restore','prepare','inspect-frozen','restore-recovery') and c['role'] != 'standby': raise ValueError('not a standby')
    if r['action'] == 'prepare-recovery' and c['role'] != 'writer': raise ValueError('not a writer')
    if r['action'] in ('freeze','restore','restore-recovery'): validate_cut(r['payload']['cut'])
    if r['action'] == 'prepare':
        p = r['payload']
        if (p['new_epoch'] != 'd1-' + r['operation']
                or not isinstance(p['signature'], dict) or set(p['signature']) != set(node.DBS)
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in [*p['signature'].values(), p['fence_digest']])):
            raise ValueError('invalid activation identity or comparison')
    if r['action'] == 'prepare-recovery':
        source = r['payload']['source_epoch']
        if (source == 'd1-' + r['operation'] or source == c['epoch']
                or not isinstance(source, str) or not re.fullmatch(r'd1-[a-z0-9-]+', source)):
            raise ValueError('invalid recovery source epoch')
    if r['action'] == 'restore-recovery':
        if (not isinstance(r['payload']['fence_digest'], str)
                or not re.fullmatch('[0-9a-f]{64}', r['payload']['fence_digest'])):
            raise ValueError('invalid recovery fence')
    if r['action'] == 'rejoin':
        if r['payload']['new_epoch'] != 'd1-' + r['operation'] or r['payload']['new_epoch'] == c['epoch']:
            raise ValueError('invalid rejoin epoch')


def logical_signature(data):
    node.validate_databases(data)
    result = {}
    for name in node.DBS:
        path = data/(name+'.db')
        # ponytail: sort full rows for the fixed demo; stream external sorting if DBs exceed 64 MiB.
        if path.stat().st_size > 64*1024*1024: raise ValueError('demo comparison size limit')
        with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            if db.execute('PRAGMA integrity_check').fetchone() != ('ok',) or db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('database integrity failure')
            schema = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()
            digest = hashlib.sha256(repr(schema).encode())
            for table, in db.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
                digest.update(table.encode())
                rows = sorted(repr(row) for row in db.execute('SELECT * FROM "'+table.replace('"','""')+'"'))
                for row in rows: digest.update(row.encode()+b'\n')
            result[name] = digest.hexdigest()
    return result


def atomic_json(path, value, mode=0o600):
    temp = path.with_name(path.name+'.pending')
    with temp.open('x') as f:
        os.fchmod(f.fileno(), mode); json.dump(value, f, allow_nan=False); f.flush(); os.fsync(f.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def status():
    with urllib.request.urlopen('http://127.0.0.1:4001/_hat/status', timeout=5) as response:
        return json.load(response)


_RESTORE_OUTPUT_LIMIT = 64 * 1024


def run(args, work, timeout=90, env=None):
    prefix = work/str(time.time_ns())
    stdout = prefix.with_suffix('.stdout')
    stderr = prefix.with_suffix('.stderr')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        p = subprocess.run(args, stdout=out, stderr=err, timeout=timeout, env=env)
    if p.returncode:
        raise RuntimeError('node command failed; protected output retained')
    try:
        if stdout.stat().st_size > _RESTORE_OUTPUT_LIMIT or stderr.stat().st_size > _RESTORE_OUTPUT_LIMIT:
            raise RuntimeError('restore cut evidence unavailable')
        return stdout.read_bytes(), stderr.read_bytes()
    except OSError as exc:
        raise RuntimeError('restore cut evidence unavailable') from None


def validate_restore_evidence(output, cut):
    """Require bounded, explicitly labeled evidence for every requested position."""
    try:
        text = bytes(output).decode('ascii')
        found = re.findall(
            r'\btxid\s*[:=]\s*([0-9a-fA-F]+)\b[\s\S]*?\bto_txid\s*[:=]\s*([0-9a-fA-F]+)\b'
            r'[\s\S]*?\bposition\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+)\b', text, re.IGNORECASE)
        expected = sorted(cut.values())
        actual = sorted((int(txid, 16), int(to_txid, 16), int(position, 0))
                        for txid, to_txid, position in found)
        if len(actual) != len(expected) or sorted((txid, txid, position) for txid, position in zip(expected, expected)) != actual:
            raise ValueError
    except (TypeError, ValueError, UnicodeError):
        raise RuntimeError('restore cut evidence unavailable') from None


def empty_cgroup():
    path = Path('/sys/fs/cgroup/system.slice/hat-demo.service/cgroup.procs')
    if path.exists() and path.read_text().strip(): raise RuntimeError('node processes remain alive')


def _pgrep(name):
    result = subprocess.run(['pgrep', '-x', name], capture_output=True, text=True)
    if result.returncode == 1 and not result.stderr.strip(): return []
    if result.returncode != 0 or result.stderr.strip():
        raise RuntimeError('mutator check failed: ' + name)
    try: return [int(value) for value in result.stdout.split()]
    except ValueError as exc: raise RuntimeError('mutator check returned invalid PIDs') from exc


def _no_known_mutators():
    """Require global pgrep to return the unambiguous 'none' result."""
    if _pgrep('trail') or _pgrep('trailbase') or _pgrep('litestream'):
        raise RuntimeError('known mutator remains')


def _follower_database(argv):
    """Exact argv emitted by node.serve(); no alternate config, output or source."""
    for db in node.DBS:
        data = str(node.BASE/'depot/data'/(db+'.db'))
        if argv == [str(node.BIN/'litestream'),'restore','-config',str(REPLICA),
                    '-f','-follow-interval','1s','-o',data,data]:
            return db
    raise RuntimeError('unknown or incorrectly bound litestream process')


def _no_writer_processes():
    if _pgrep('trail') or _pgrep('trailbase'):
        raise RuntimeError('writer process remains')
    for pid in _pgrep('litestream'):
        _follower_database(_process_commandline(pid))


def _service_safety():
    enabled = subprocess.run(['systemctl', 'is-enabled', 'hat-demo.service'], capture_output=True, text=True)
    enabled_value = enabled.stdout.strip()
    if enabled.returncode not in (0, 1) or enabled_value not in ('static', 'disabled'):
        raise RuntimeError('autonomous node boot is enabled or unconfirmed')
    restart = subprocess.run(['systemctl', 'show', '-p', 'Restart', '--value', 'hat-demo.service'],
                             capture_output=True, text=True)
    if restart.returncode or restart.stdout.strip() != 'no':
        raise RuntimeError('automatic node restart enabled or unconfirmed')
    for unit in ('hat-trailbase.service', 'hat-litestream.service'):
        result = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
        if result.returncode not in (0, 1) or result.stdout.strip() != 'masked':
            raise RuntimeError('legacy writable service is not masked or unconfirmed')
    return dict(node_service=enabled_value, restart='no', legacy_services='masked')


def _cold_safety():
    empty_cgroup()
    services = _service_safety()
    _no_known_mutators()
    return services


def _authority_state(c):
    if not node.AUTHORITY.exists() and not node.AUTHORITY.is_symlink():
        return 'absent'
    try:
        s = node.AUTHORITY.lstat()
        if (node.AUTHORITY.is_symlink() or s.st_uid != 0 or (s.st_mode & 0o7777) != 0o644 or s.st_nlink != 1):
            return 'unsafe'
        node.regular_file(node.AUTHORITY)
        value = json.loads(node.AUTHORITY.read_text())
    except (OSError, ValueError, TypeError, KeyError):
        raise RuntimeError('unsafe activation authority')
    if (not isinstance(value, dict) or set(value) != {'role','epoch','boot_id'}
            or value['role'] != 'writer' or not isinstance(value['epoch'], str)
            or not re.fullmatch(r'd1-[a-z0-9-]+', value['epoch'])
            or not isinstance(value['boot_id'], str) or not value['boot_id']):
        raise RuntimeError('invalid activation authority')
    current_boot = node.boot_id()
    if value.get('boot_id') == current_boot:
        if not node.authorized(c['role'], c['epoch'], current_boot, value):
            raise RuntimeError('current-boot activation authority mismatch')
        return 'current'
    if not node.authorized('writer', value.get('epoch'), value.get('boot_id'), value):
        raise RuntimeError('invalid activation authority')
    return 'stale'


def inspect_cold(r, c):
    """Read-only cold inspection; liveness comes from independent local checks."""
    services = _cold_safety()
    authority = _authority_state(c)
    if authority == 'unsafe':
        raise RuntimeError('unsafe activation authority')
    if authority == 'current' and c['role'] == 'writer':
        raise RuntimeError('current-boot writable authority remains')
    return dict(operation=r['operation'], epoch=c['epoch'], boot_id=node.boot_id(),
                authority=authority, services=services, cgroup='empty', mutators='none',
                config=c, replica_config=REPLICA.read_text(),
                config_sha=hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
                replica_sha=hashlib.sha256(REPLICA.read_bytes()).hexdigest())


def replace_replica_prefix(text, old_epoch, new_epoch):
    for db in node.DBS:
        pattern = re.compile(r'(?m)^([ \t]*path:[ \t]*)demos/' + re.escape(old_epoch) + '/' + db
                            + r'([ \t]*(?:#.*)?)(?=\r?$)')
        if len(pattern.findall(text)) != 1:
            raise RuntimeError('unexpected backup prefix configuration')
        text = pattern.sub(r'\1demos/' + new_epoch + '/' + db + r'\2', text)
    return text


def _write_replica(text):
    temp = REPLICA.with_name(REPLICA.name + '.pending')
    with temp.open('x') as f:
        os.fchmod(f.fileno(), 0o640)
        os.fchown(f.fileno(), 0, pwd.getpwnam('hat-demo').pw_gid)
        f.write(text); f.flush(); os.fsync(f.fileno())
    os.replace(temp, REPLICA)
    fd = os.open(REPLICA.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _retain_file(path, destination):
    node.regular_file(path)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('retained evidence already exists; reconciliation required')
    shutil.copy2(path, destination)


def _completed_record(work, name):
    path = work / (name + '.json')
    if not path.exists() and not path.is_symlink():
        return None
    s = path.lstat()
    if (path.is_symlink() or not path.is_file() or s.st_uid != os.geteuid()
            or s.st_mode & 0o077 or s.st_nlink != 1):
        raise ValueError('unsafe recovery record')
    value = json.loads(path.read_text())
    if value.get('status') != 'done':
        raise RuntimeError(name + ' is incomplete; reconciliation required')
    return value


def prepare_recovery(r, c, work):
    _cold_safety()
    authority = _authority_state(c)
    if authority in ('current', 'unsafe'):
        raise RuntimeError('current or unsafe writable authority remains')
    source_epoch = r['payload']['source_epoch']
    original_config_sha = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    original_replica_sha = hashlib.sha256(REPLICA.read_bytes()).hexdigest()
    _retain_file(CONFIG, work / 'original-config.json')
    _retain_file(REPLICA, work / 'original-litestream.yml')
    text = replace_replica_prefix(REPLICA.read_text(), c['epoch'], source_epoch)
    future = dict(c, role='standby', epoch=source_epoch, bootstrap=False)
    atomic_json(CONFIG, future, 0o640)
    account = pwd.getpwnam('hat-demo')
    os.chown(CONFIG, 0, account.pw_gid)
    _write_replica(text)
    node.load_config(CONFIG)
    return dict(operation=r['operation'], original_epoch=c['epoch'], original_boot_id=r['boot_id'],
                original_config_sha=original_config_sha, original_replica_sha=original_replica_sha,
                epoch=source_epoch, role='standby')


def _backup_credentials():
    env_path = BACKUP_ENV; s = node.regular_file(env_path)
    if s.st_uid != 0 or s.st_mode & 0o077:
        raise ValueError('unsafe backup environment')
    values = {}
    for line in env_path.read_text().splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in values:
            raise ValueError('invalid backup environment')
        values[key] = json.loads(value)
    if set(values) != {'IDRIVE_ACCESS_KEY_ID', 'IDRIVE_SECRET_ACCESS_KEY'} or any(not isinstance(v, str) or not v for v in values.values()):
        raise ValueError('invalid backup credential fields')
    return values


def _finite_restore(cut, fresh, work):
    values = _backup_credentials()
    fresh.mkdir(mode=0o700)
    directory = fresh.lstat()
    if (not fresh.is_dir() or fresh.is_symlink()
            or directory.st_uid != os.geteuid() or directory.st_mode & 0o077
            or any(parent.is_symlink() for parent in fresh.parents)):
        raise RuntimeError('unsafe restore directory')
    for db, position in cut.items():
        output = fresh / (db + '.db')
        stdout, stderr = run([str(node.BIN/'litestream'), 'restore', '-config', str(REPLICA), '-txid', f'{position:016x}',
             '-o', str(output), str(node.BASE/'depot/data'/(db+'.db'))], work, timeout=45,
            env=dict(os.environ, **values))
        validate_restore_evidence(stdout + b'\\n' + stderr, {db: position})
        try:
            s = output.lstat()
            if (not output.is_file() or output.is_symlink() or s.st_nlink != 1
                    or s.st_uid != os.geteuid() or s.st_mode & 0o077
                    or any(parent.is_symlink() for parent in output.parents)):
                raise RuntimeError('unsafe restored output')
        except OSError as exc:
            raise RuntimeError('restore output unavailable') from exc
    return logical_signature(fresh)


def restore_recovery(r, c, work):
    _cold_safety()
    prepared = _completed_record(work, 'prepare-recovery')
    if prepared is None:
        raise RuntimeError('recovery preparation is not complete')
    request = prepared.get('request', {}); result = prepared.get('result', {})
    if (request.get('operation') != r['operation'] or request.get('epoch') != result.get('original_epoch')
            or request.get('boot_id') != r['boot_id']
            or request.get('payload', {}).get('source_epoch') != c['epoch']
            or result.get('epoch') != c['epoch'] or result.get('role') != 'standby'
            or result.get('original_boot_id') != request.get('boot_id')):
        raise RuntimeError('recovery preparation binding differs')
    cut = r['payload']['cut']
    fresh = work / 'fresh-restore'
    if fresh.exists() or fresh.is_symlink():
        raise RuntimeError('restore workspace already exists; reconciliation required')
    signature = _finite_restore(cut, fresh, work)
    result = dict(operation=r['operation'], original_epoch=prepared['result']['original_epoch'],
                  original_boot_id=prepared['result']['original_boot_id'], epoch=c['epoch'],
                  cut=cut, signature=signature, fence_digest=r['payload']['fence_digest'],
                  source_epoch=c['epoch'], request=dict(operation=r['operation'], epoch=c['epoch'],
                  boot_id=r['boot_id']))
    return result


def _process_commandline(pid):
    try:
        raw = Path('/proc/' + str(pid) + '/cmdline').read_bytes()
        argv = raw.rstrip(b'\0').split(b'\0')
        if not argv or any(not item for item in argv): raise RuntimeError('invalid process command line')
        return [item.decode() for item in argv]
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise RuntimeError('unreadable process command line') from exc


def _standby_health(value, epoch, cut, boot_id=None):
    """Accept only node's bounded follower startup states, never an arbitrary refusal."""
    if (not isinstance(value, dict) or value.get('role') != 'standby' or value.get('epoch') != epoch
            or type(value.get('healthy')) is not bool):
        raise RuntimeError('standby identity is unconfirmed')
    if boot_id is not None and 'boot_id' in value and value['boot_id'] != boot_id:
        raise RuntimeError('standby boot binding changed')
    if value.get('trailbase_running') is not False and value.get('trailbase_running') is not None:
        raise RuntimeError('standby has a writer process')
    phase = value.get('phase')
    refusals = value.get('refusals')
    if not isinstance(refusals, list) or any(not isinstance(item, str) for item in refusals):
        raise RuntimeError('standby refusal state is unconfirmed')
    # The real producer starts with sampled_at=0 before its first loop sample.
    initial = {'starting','position sample stale or clock changed','required database positions unconfirmed'}
    if (value.get('sampled_at') == 0 and value.get('positions') == {}
            and value.get('processes') is None and phase is None
            and set(refusals) == initial and len(refusals) == len(initial) and not value['healthy']):
        return value
    allowed = {'starting', 'required database positions unconfirmed'}
    for db in node.DBS:
        allowed.update((db + ': database not yet restored', db + ': position unconfirmed'))
    if any(item not in allowed for item in refusals):
        raise RuntimeError('standby refusal is not a bounded startup state')
    if phase not in (None, 'starting', 'restoring'):
        raise RuntimeError('standby phase is not a bounded startup state')
    positions = value.get('positions')
    if not isinstance(positions, dict) or not set(positions).issubset(node.DBS):
        raise RuntimeError('standby positions are unconfirmed')
    if any(type(v) is not int or v <= 0 for v in positions.values()):
        raise RuntimeError('standby positions are unconfirmed')
    if any(positions[db] < position for db, position in cut.items() if db in positions):
        raise RuntimeError('standby cut is behind the required cut')
    processes = value.get('processes')
    if (not isinstance(processes, dict) or set(processes) != set(node.DBS)
            or any(type(v) is not bool or not v for v in processes.values())):
        raise RuntimeError('standby follower process exited')
    if value['healthy']:
        if (set(positions) != set(node.DBS) or processes is None or refusals
                or phase is not None or value.get('trailbase_running') is not False):
            raise RuntimeError('standby readiness is incomplete or inconsistent')
        return value
    if phase not in (None, 'starting', 'restoring'):
        raise RuntimeError('standby health is unconfirmed')
    return value


def _standby_processes_alive(value):
    """Validate every globally visible litestream is the node's follower form."""
    processes = value.get('processes')
    if (not isinstance(processes, dict) or set(processes) != set(node.DBS)
            or any(item is not True for item in processes.values())):
        raise RuntimeError('follower process health map is malformed')
    pids = _pgrep('litestream')
    if len(pids) != len(node.DBS):
        raise RuntimeError('follower process set is unconfirmed')
    databases = [_follower_database(_process_commandline(pid)) for pid in pids]
    if set(databases) != set(node.DBS):
        raise RuntimeError('follower databases are duplicate or missing')


def rejoin(r, c, work):
    _cold_safety()
    if node.boot_id() != r['boot_id']:
        raise RuntimeError('rejoin boot binding changed')
    authority = _authority_state(c)
    if authority in ('current', 'unsafe'):
        raise RuntimeError('current or unsafe writable authority remains')
    new_epoch = r['payload']['new_epoch']
    original_config_sha = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    original_replica_sha = hashlib.sha256(REPLICA.read_bytes()).hexdigest()
    _retain_file(CONFIG, work / 'original-config.json')
    _retain_file(REPLICA, work / 'original-litestream.yml')
    if node.AUTHORITY.exists() or node.AUTHORITY.is_symlink():
        _retain_file(node.AUTHORITY, work / 'original-activation.json')
        node.AUTHORITY.unlink()
    meta = node.BASE / 'meta'
    if meta.is_symlink() or any(p.is_symlink() for p in meta.parents):
        raise RuntimeError('symlinked original metadata directory')
    if meta.exists():
        retained_meta = node.BASE / ('retained-meta-' + r['operation'])
        if retained_meta.exists() or retained_meta.is_symlink(): raise RuntimeError('retained metadata already exists')
        meta.rename(retained_meta)
    data = node.BASE / 'depot/data'
    if data.is_symlink() or not data.is_dir() or any(p.is_symlink() for p in data.parents):
        raise RuntimeError('symlinked or missing original data directory')
    if data.exists():
        retained = node.BASE / ('retained-data-' + r['operation'])
        if retained.exists() or retained.is_symlink(): raise RuntimeError('retained data already exists')
        data.rename(retained)
    data.mkdir(mode=0o700)
    account = pwd.getpwnam('hat-demo')
    os.chown(data, account.pw_uid, account.pw_gid)
    text = replace_replica_prefix(REPLICA.read_text(), c['epoch'], new_epoch)
    future = dict(c, role='standby', epoch=new_epoch, bootstrap=False)
    atomic_json(CONFIG, future, 0o640); os.chown(CONFIG, 0, account.pw_gid)
    _write_replica(text); node.load_config(CONFIG)
    subprocess.run(['systemctl', 'start', 'hat-demo.service'], check=True, timeout=60)
    if node.boot_id() != r['boot_id']:
        raise RuntimeError('rejoin boot binding changed')
    deadline = time.monotonic() + 90
    while True:
        try:
            value = _standby_health(status(), new_epoch, {db: 1 for db in node.DBS}, r['boot_id'])
            # The native producer's exact initial sample has no process map yet.
            if value.get('processes') is not None:
                _standby_processes_alive(value)
            if value.get('healthy'):
                break
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError('standby startup unconfirmed')
        time.sleep(1)
    _no_writer_processes()
    return dict(operation=r['operation'], original_epoch=c['epoch'], original_boot_id=r['boot_id'],
                original_config_sha=original_config_sha, original_replica_sha=original_replica_sha,
                epoch=new_epoch, role='standby', cut=value['positions'], healthy=True)


def execute(r, c, work):
    action = r['action']; data = node.BASE/'depot/data'
    if action == 'inspect-cold':
        return inspect_cold(r, c)
    if action == 'prepare-recovery':
        return prepare_recovery(r, c, work)
    if action == 'restore-recovery':
        return restore_recovery(r, c, work)
    if action == 'rejoin':
        return rejoin(r, c, work)
    if action == 'quiesce':
        before = status()
        if not before['healthy'] or not before['trailbase_running']: raise RuntimeError('source not healthy')
        atomic_json(Path('/run/hat-node-quiesce.json'), {k:r[k] for k in ('operation','epoch','boot_id')}, 0o644)
        run(['systemctl','kill','--kill-whom=main','--signal=SIGUSR1','hat-demo.service'], work)
        deadline = time.monotonic()+100
        while True:
            value = status()
            if value.get('phase') == 'quiesced' and value.get('operation') == r['operation']: break
            if time.monotonic() > deadline: raise RuntimeError('quiesce outcome unknown')
            time.sleep(.5)
        validate_cut(value['cut'])
        main = int(subprocess.check_output(['systemctl','show','-p','MainPID','--value','hat-demo.service']))
        if set(map(int, Path('/sys/fs/cgroup/system.slice/hat-demo.service/cgroup.procs').read_text().split())) != {main}:
            raise RuntimeError('mutators still present after cut')
        if not node.authority(c): raise RuntimeError('source authority changed')
        shutil.copy2(node.AUTHORITY, work/'retained-activation.json')
        node.AUTHORITY.unlink()  # Retained above; boot/epoch authority is deliberately revoked.
        return value
    if action == 'freeze':
        cut = r['payload']['cut']; before = status()
        if before['role'] != 'standby' or not before['healthy'] or before['epoch'] != c['epoch']:
            raise RuntimeError('candidate not eligible')
        deadline = time.monotonic()+90
        while not all(before['positions'].get(db,0) >= pos for db,pos in cut.items()):
            if time.monotonic() > deadline: raise RuntimeError('candidate did not reach cut')
            time.sleep(1); before = status()
            if not before['healthy']: raise RuntimeError('candidate lost health')
        run(['systemctl','stop','hat-demo.service'], work)
        empty_cgroup()
        for db, position in cut.items():
            sidecar = data/(db+'.db-txid'); node.regular_file(sidecar)
            if node.txid(sidecar.read_text().strip()) != position: raise RuntimeError('frozen candidate cut differs')
        node.validate_databases(data)
        frozen = work/'frozen'; frozen.mkdir(mode=0o700)
        for db in node.DBS:
            with sqlite3.connect((data/(db+'.db')).as_uri()+'?mode=ro', uri=True) as source, sqlite3.connect(frozen/(db+'.db')) as dest:
                source.backup(dest)
        return dict(cut=cut, signature=logical_signature(frozen))
    if action == 'restore':
        empty_cgroup()
        prior = json.loads((work/'freeze.json').read_text())
        if prior.get('status') != 'done' or prior['result']['cut'] != r['payload']['cut']:
            raise RuntimeError('fresh restore requires a completed freeze at the same cut')
        fresh = work/'fresh-restore'
        signature = _finite_restore(r['payload']['cut'], fresh, work)
        (work/'frozen').rename(work/'rejected-follower')
        fresh.rename(work/'frozen')
        return dict(cut=r['payload']['cut'],signature=signature,source='fresh-restore')
    if action == 'prepare':
        empty_cgroup()
        if node.AUTHORITY.exists() or node.AUTHORITY.is_symlink(): raise RuntimeError('unexpected candidate activation')
        recovery = _completed_record(work, 'restore-recovery')
        if recovery is not None:
            selected, restored = work/'restore-recovery.json', work/'fresh-restore'
            previous = recovery
        else:
            selected = work/('restore.json' if (work/'restore.json').exists() else 'freeze.json')
            restored = work/'frozen'
            previous = json.loads(selected.read_text())
        expected = r['payload']['signature']
        if selected.name == 'restore-recovery.json':
            recovery_request = previous.get('request', {})
            recovery_result = previous.get('result', {})
            if (recovery_request.get('action') != 'restore-recovery'
                    or recovery_request.get('operation') != r['operation']
                    or recovery_request.get('epoch') != c['epoch']
                    or recovery_request.get('boot_id') != r['boot_id']
                    or recovery_result.get('epoch') != c['epoch']
                    or recovery_result.get('fence_digest') != r['payload']['fence_digest']):
                raise RuntimeError('recovery restore binding differs')
        if (previous.get('status') != 'done' or previous['result']['signature'] != expected
                or logical_signature(restored) != expected):
            raise RuntimeError('frozen comparison not confirmed')
        account = pwd.getpwnam('hat-demo')
        for src in (CONFIG, REPLICA): shutil.copy2(src, work/src.name)
        text = replace_replica_prefix(REPLICA.read_text(), c['epoch'], r['payload']['new_epoch'])
        data.rename(node.BASE/('retained-data-'+r['operation']))
        meta = node.BASE/'meta'
        if meta.is_symlink(): raise RuntimeError('symlinked replica metadata')
        if meta.exists(): meta.rename(node.BASE/('retained-meta-'+r['operation']))
        data.mkdir(mode=0o700)
        for db in node.DBS: shutil.copy2(restored/(db+'.db'),data/(db+'.db'))
        for p in (data, *data.iterdir()): os.chown(p, account.pw_uid, account.pw_gid)
        future = dict(c, role='writer', epoch=r['payload']['new_epoch'], bootstrap=False)
        atomic_json(CONFIG, future, 0o640); os.chown(CONFIG, 0, account.pw_gid)
        temp = REPLICA.with_name('litestream.yml.pending')
        with temp.open('x') as f:
            os.fchmod(f.fileno(), 0o640); os.fchown(f.fileno(),0,account.pw_gid)
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(temp, REPLICA)
        fd = os.open(REPLICA.parent, os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        node.load_config(CONFIG)
        return dict(epoch=future['epoch'], signature=expected, fence_digest=r['payload']['fence_digest'])
    if action == 'activate':
        empty_cgroup()
        prepared = json.loads((work/'prepare.json').read_text())
        if (prepared.get('status') != 'done' or prepared['result']['epoch'] != c['epoch']
                or prepared['request']['boot_id'] != node.boot_id()
                or logical_signature(data) != prepared['result']['signature']):
            raise RuntimeError('candidate activation not prepared')
        node.activate(c)
        deadline = time.monotonic()+90
        while True:
            try:
                value = status()
                if value['healthy'] and value['epoch'] == c['epoch'] and value['trailbase_running']: return value
            except OSError: pass
            if time.monotonic() > deadline: raise RuntimeError('candidate startup unconfirmed')
            time.sleep(1)
    raise ValueError('unsupported mutation')


def main():
    if os.geteuid() != 0: raise ValueError('root controller required')
    if sys.argv[1:] != ['local'] and (sys.argv[1:] != ['remote'] or os.environ.get('SSH_ORIGINAL_COMMAND') != 'hat-node'):
        raise ValueError('only the fixed node request dispatcher is allowed')
    os.umask(0o077)
    raw = sys.stdin.buffer.read(1024*1024+1)
    if len(raw) > 1024*1024: raise ValueError('request too large')
    r = json.loads(raw); c = node.load_config(CONFIG)
    validate_request(r, c, node.boot_id())
    if r['action'] == 'probe':
        value = status()
        if not value['healthy']: raise RuntimeError('node health refused')
        enabled = subprocess.run(['systemctl','is-enabled','hat-demo.service'], capture_output=True, text=True).stdout.strip()
        if enabled not in ('static','disabled'): raise RuntimeError('autonomous node boot is enabled')
        if subprocess.check_output(['systemctl','show','-p','Restart','--value','hat-demo.service']).strip() != b'no':
            raise RuntimeError('automatic node restart enabled')
        for unit in ('hat-trailbase.service','hat-litestream.service'):
            if subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True).stdout.strip() != 'masked':
                raise RuntimeError('legacy writable service not masked')
        print(json.dumps(dict(config=c, boot_id=node.boot_id(), status=value, replica_config=REPLICA.read_text())))
        return
    STATE.mkdir(mode=0o700, exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise ValueError('unsafe node journal directory')
    for directory in (STATE.parent, STATE):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)
    lock_fd = os.open(STATE/'lock', os.O_CREAT | os.O_APPEND | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'a') as lock:
        lock_stat = os.fstat(lock.fileno())
        if (lock_stat.st_uid != os.geteuid() or lock_stat.st_mode & 0o077 or lock_stat.st_nlink != 1):
            raise ValueError('unsafe node lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        c = node.load_config(CONFIG); validate_request(r, c, node.boot_id())
        fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        if r['action']=='inspect-cold':
            print(json.dumps(inspect_cold(r, c)))
            return
        work = STATE/r['operation']; work.mkdir(mode=0o700, exist_ok=True)
        work_stat = work.lstat()
        if (work.is_symlink() or not work.is_dir() or work_stat.st_uid != os.geteuid()
                or work_stat.st_mode & 0o077 or any(parent.is_symlink() for parent in work.parents)):
            raise ValueError('unsafe operation directory')
        if r['action']=='inspect-frozen':
            empty_cgroup()
            if node.AUTHORITY.exists() or node.AUTHORITY.is_symlink():raise RuntimeError('candidate has activation authority')
            if any((work/(a+'.json')).exists() for a in ('restore','prepare','activate')):raise RuntimeError('candidate advanced beyond freeze')
            prior=json.loads((work/'freeze.json').read_text())
            if prior.get('status')!='done' or any(prior['request'][k]!=r[k] for k in ('operation','epoch','boot_id')):
                raise RuntimeError('frozen request binding differs')
            validate_cut(prior['result']['cut'])
            if logical_signature(work/'frozen')!=prior['result']['signature']:raise RuntimeError('frozen data changed')
            print(json.dumps(dict(config=c,boot_id=node.boot_id(),frozen=prior['result'],replica_config=REPLICA.read_text())))
            return
        record = work/(r['action']+'.json')
        if record.exists() or record.is_symlink(): raise RuntimeError('operation already attempted; reconciliation required')
        atomic_json(record, dict(status='intent', request=r))
        result = execute(r, c, work)
        atomic_json(record, dict(status='done', request=r, result=result))
        print(json.dumps(result))

if __name__ == '__main__': main()
