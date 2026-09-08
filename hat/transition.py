#!/usr/bin/env python3
"""Fixed root-only D2 node operations, reached through a dedicated forced SSH command."""
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
              'prepare': {'new_epoch', 'signature', 'fence_digest'}, 'activate': set(), 'inspect-frozen': set()}
    if not isinstance(r, dict) or set(r) != {'action','operation','epoch','boot_id','payload'}:
        raise ValueError('invalid request shape')
    if (r['action'] not in shapes or not isinstance(r['operation'], str)
            or not re.fullmatch('[0-9a-f]{32}', r['operation']) or r['epoch'] != c['epoch']
            or (r['boot_id'] != boot and not (r['action'] == 'probe' and r['boot_id'] is None))
            or not isinstance(r['payload'], dict) or set(r['payload']) != shapes[r['action']]):
        raise ValueError('invalid operation, epoch, boot or payload')
    if r['action'] in ('quiesce','activate') and c['role'] != 'writer': raise ValueError('not a writer')
    if r['action'] in ('freeze','restore','prepare','inspect-frozen') and c['role'] != 'standby': raise ValueError('not a standby')
    if r['action'] in ('freeze','restore'): validate_cut(r['payload']['cut'])
    if r['action'] == 'prepare':
        p = r['payload']
        if (p['new_epoch'] != 'd1-'+r['operation'] or p['new_epoch'] == c['epoch']
                or not isinstance(p['signature'], dict) or set(p['signature']) != set(node.DBS)
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in [*p['signature'].values(), p['fence_digest']])):
            raise ValueError('invalid activation identity or comparison')


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


def run(args, work, timeout=90, env=None):
    prefix = work/str(time.time_ns())
    with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
        p = subprocess.run(args, stdout=out, stderr=err, timeout=timeout, env=env)
    if p.returncode: raise RuntimeError('node command failed; protected output retained')


def empty_cgroup():
    path = Path('/sys/fs/cgroup/system.slice/hat-demo.service/cgroup.procs')
    if path.exists() and path.read_text().strip(): raise RuntimeError('node processes remain alive')


def execute(r, c, work):
    action = r['action']; data = node.BASE/'depot/data'
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
        env_path = BACKUP_ENV; s = node.regular_file(env_path)
        if s.st_uid != 0 or s.st_mode & 0o077: raise ValueError('unsafe backup environment')
        values = {}
        for line in env_path.read_text().splitlines():
            key, separator, value = line.partition('=')
            if not separator or key in values: raise ValueError('invalid backup environment')
            values[key] = json.loads(value)
        if set(values) != {'IDRIVE_ACCESS_KEY_ID','IDRIVE_SECRET_ACCESS_KEY'} or any(not isinstance(v,str) or not v for v in values.values()):
            raise ValueError('invalid backup credential fields')
        fresh = work/'fresh-restore'; fresh.mkdir(mode=0o700)
        for db, position in r['payload']['cut'].items():
            run([str(node.BIN/'litestream'),'restore','-config',str(REPLICA),'-txid',f'{position:016x}',
                 '-o',str(fresh/(db+'.db')),str(data/(db+'.db'))],work,timeout=45,env=dict(os.environ,**values))
        signature = logical_signature(fresh)
        (work/'frozen').rename(work/'rejected-follower')
        fresh.rename(work/'frozen')
        return dict(cut=r['payload']['cut'],signature=signature,source='fresh-restore')
    if action == 'prepare':
        empty_cgroup()
        if node.AUTHORITY.exists() or node.AUTHORITY.is_symlink(): raise RuntimeError('unexpected candidate activation')
        selected = work/('restore.json' if (work/'restore.json').exists() else 'freeze.json')
        previous = json.loads(selected.read_text())
        expected = r['payload']['signature']
        if previous.get('status') != 'done' or previous['result']['signature'] != expected or logical_signature(work/'frozen') != expected:
            raise RuntimeError('frozen comparison not confirmed')
        account = pwd.getpwnam('hat-demo')
        for src in (CONFIG, REPLICA): shutil.copy2(src, work/src.name)
        text = REPLICA.read_text()
        for db in node.DBS:
            old = 'path: demos/'+c['epoch']+'/'+db
            if text.count(old) != 1: raise RuntimeError('unexpected backup prefix configuration')
            text = text.replace(old, 'path: demos/'+r['payload']['new_epoch']+'/'+db)
        data.rename(node.BASE/('retained-data-'+r['operation']))
        meta = node.BASE/'meta'
        if meta.is_symlink(): raise RuntimeError('symlinked replica metadata')
        if meta.exists(): meta.rename(node.BASE/('retained-meta-'+r['operation']))
        data.mkdir(mode=0o700)
        for db in node.DBS: shutil.copy2(work/'frozen'/(db+'.db'),data/(db+'.db'))
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
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        c = node.load_config(CONFIG); validate_request(r, c, node.boot_id())
        work = STATE/r['operation']; work.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        if work.is_symlink(): raise ValueError('symlinked operation directory')
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
