#!/usr/bin/env python3
"""D1 fixed-role demo node. No election, promotion, fencing or automatic writer restart."""
import argparse
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import threading
import time
import urllib.request

DBS = ('main', 'session', 'aux')
BASE = Path('/var/lib/hat-demo')
RUN = Path('/run/hat-demo')
AUTHORITY = Path('/run/hat-demo-activation.json')
BIN = Path('/opt/hat-demo/bin')


def txid(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{16}', value):
        raise ValueError('invalid TXID sidecar')
    return int(value, 16)


def sync_position(value, database):
    if (not isinstance(value, dict) or set(value) != {'db_path', 'txid', 'replica_txid', 'duration_ms'}
            or value['db_path'] != database
            or any(type(value[k]) is not int or value[k] < 0 for k in ('txid', 'replica_txid', 'duration_ms'))
            or value['txid'] != value['replica_txid']):
        raise ValueError('unconfirmed replica position')
    return value['replica_txid']


def authorized(role, epoch, boot_id, record):
    return role == 'writer' and record == dict(role=role, epoch=epoch, boot_id=boot_id)


# Pinned real uploader/follower records in tests/fixtures; unknown events refuse health.
LOG_FIELDS = {
    'litestream': 'version',
    'retention disabled; cloud provider lifecycle policies must handle retention': 'hint',
    'control socket listening': 'system path',
    'initialized db': 'path',
    'replicating to': 'type sync-interval bucket path region endpoint',
    'starting compaction monitor': 'system interval',
    'starting L0 retention monitor': 'system interval retention',
    'snapshot complete': 'system db txid size',
    'compaction complete': 'system db txid size',
    'signal received, litestream shutting down': 'signal',
    'litestream shut down': '',
    'l0 retention enforced': 'system db deleted_count max_l1_txid',
    'entering follow mode': 'db replica output txid interval',
    'follow: applied updates': 'db replica from_txid to_txid',
}


def log_bad(line):
    try:
        pairs = json.loads(line, object_pairs_hook=lambda p: p)
        if not isinstance(pairs, list) or any(not isinstance(p, tuple) or len(p) != 2 for p in pairs):
            return True
        value = dict(pairs)
        duplicates = [k for k in value if sum(key == k for key, _ in pairs) > 1]
        if duplicates:
            levels = [v for k, v in pairs if k == 'level']
            startup = levels == ['INFO', ''] and value.get('msg') == 'litestream' and value.get('version') == '0.5.17'
            compaction = (len(levels) == 2 and levels[0] == 'INFO' and type(levels[1]) is int
                          and levels[1] in (1, 2, 3, 9) and value.get('msg') in ('starting compaction monitor', 'compaction complete'))
            if duplicates != ['level'] or not (startup or compaction): return True
            value['level'] = 'INFO'
        message = value.get('msg')
        if message not in LOG_FIELDS: return True
        fields = set(LOG_FIELDS[message].split())
        if set(value) - {'time', 'level', 'msg'} != fields: return True
        level = 'WARN' if message.startswith('retention disabled;') else 'INFO'
        if value.get('level') != level: return True
        for name in fields | ({'time'} if 'time' in value else set()):
            item = value[name]
            if name in {'interval', 'retention', 'sync-interval', 'size', 'signal', 'deleted_count'}:
                if type(item) is not int or item < 0: return True
            elif name == 'txid' and message == 'compaction complete':
                if not isinstance(item, list) or len(item) != 2: return True
                bounds = dict(item)
                if set(bounds) != {'min', 'max'} or txid(bounds['min']) > txid(bounds['max']): return True
            elif name in {'txid', 'from_txid', 'to_txid', 'max_l1_txid'}:
                txid(item)
            elif not isinstance(item, str) or not item:
                return True
        return message == 'litestream' and value['version'] != '0.5.17'
    except (ValueError, TypeError):
        return True


def public_status(state, now):
    result = dict(state)
    reasons = list(state['refusals'])
    if not 0 <= now - state['sampled_at'] <= 30:
        reasons.append('position sample stale or clock changed')
    if set(state['positions']) != set(DBS) or any(type(v) is not int or v <= 0 for v in state['positions'].values()):
        reasons.append('required database positions unconfirmed')
    result.update(healthy=not reasons, refusals=reasons, promotion_ready=False,
                  limitation='D1 transport observation only; no failover readiness or RPO bound')
    return result


def regular_file(path):
    try:
        s = path.lstat()
        if (not stat.S_ISREG(s.st_mode) or s.st_size == 0
                or any(parent.is_symlink() for parent in path.parents)):
            raise ValueError('expected nonempty regular file without symlink ancestors')
        return s
    except OSError as exc:
        raise ValueError('required file unavailable') from exc


def database_identity(path):
    s = regular_file(path)
    with path.open('rb') as f:
        if f.read(16) != b'SQLite format 3\x00':
            raise ValueError('invalid database header')
    return s.st_dev, s.st_ino


def validate_databases(data, bootstrap=False):
    if data.is_symlink() or any(p.is_symlink() for p in data.parents):
        raise ValueError('symlinked database directory')
    if bootstrap and not any(data.iterdir()): return
    if {p.stem for p in data.glob('*.db')} - set(DBS) - {'logs'}:
        raise ValueError('unenrolled database')
    for name in DBS:
        path = data / (name + '.db')
        database_identity(path)
        try:
            with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
                db.execute('PRAGMA ignore_check_constraints=ON')
                if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise ValueError('invalid database structure')
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
                required = {'hat_ops', '_user'} if name == 'main' else {'_session'} if name == 'session' else {'hat_ops'}
                if not required <= tables: raise ValueError('required fixture schema absent')
                if name != 'session': db.execute('SELECT id, op_key, payload FROM hat_ops LIMIT 0')
                if name == 'main': db.execute('SELECT id FROM _user LIMIT 0')
                if name == 'session': db.execute('SELECT id FROM _session LIMIT 0')
        except sqlite3.DatabaseError as exc:
            raise ValueError('invalid database schema') from exc


def validate_support(depot, support, bootstrap=False):
    required = {'config.textproto', 'migrations/main/U100__hat_ops.sql', 'migrations/aux/U100__hat_ops.sql'}
    if not bootstrap: required |= {'secrets/keys/private_key.pem', 'secrets/keys/public_key.pem'}
    if not isinstance(support, dict) or set(support) != required:
        raise ValueError('fixed D1 identity anchors required')
    for name, digest in support.items():
        path = depot / name  # Exact fixed set above excludes absolute/traversing paths.
        regular_file(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('application identity mismatch')


def load_config(path):
    p = Path(path)
    s = regular_file(p)
    if s.st_uid != 0 or s.st_mode & 0o022:
        raise ValueError('config must be root-owned and not writable by group/other')
    c = json.loads(p.read_text())
    if c['role'] not in ('writer', 'standby') or not re.fullmatch(r'd1-[a-z0-9-]+', c['epoch']):
        raise ValueError('invalid fixed role/epoch')
    if c['hostname'] != socket.gethostname():
        raise ValueError('wrong node identity')
    if set(c['binaries']) != {'trail', 'litestream'}:
        raise ValueError('missing binary fingerprints')
    for name, digest in c['binaries'].items():
        regular_file(BIN / name)
        if hashlib.sha256((BIN / name).read_bytes()).hexdigest() != digest:
            raise ValueError('binary fingerprint mismatch')
    if type(c.get('bootstrap', False)) is not bool or (c.get('bootstrap') and c['role'] != 'writer'):
        raise ValueError('invalid bootstrap policy')
    validate_support(BASE / 'depot', c.get('support'), c.get('bootstrap', False))
    return c


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def authority(c):
    try:
        s = AUTHORITY.lstat()
        if AUTHORITY.is_symlink() or s.st_uid != 0 or s.st_mode & 0o022:
            return False
        return authorized(c['role'], c['epoch'], boot_id(), json.loads(AUTHORITY.read_text()))
    except (OSError, ValueError):
        return False


def activate(c):
    if os.geteuid() != 0 or c['role'] != 'writer':
        raise ValueError('only root may activate the designated D1 writer; standby promotion is not implemented')
    # /run disappears on reboot; a successful old activation is never a boot instruction.
    with AUTHORITY.open('x') as f:
        os.fchmod(f.fileno(), 0o644)
        json.dump(dict(role='writer', epoch=c['epoch'], boot_id=boot_id()), f)
        f.flush()
        os.fsync(f.fileno())
    subprocess.run(['systemctl', 'start', 'hat-demo.service'], check=True)


def graceful_stop(child, timeout=15):
    if child.poll() is not None: raise RuntimeError('mutator exited before graceful stop')
    child.terminate()
    try: code = child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill(); child.wait()
        raise RuntimeError('forced stop cannot establish a planned cut')
    if code not in (0, -signal.SIGTERM): raise RuntimeError('process failed during graceful stop')
    return code


def quiesce_owned(children, sync, verify_mutators_stopped):
    trail_exit = graceful_stop(children['trail'])
    verify_mutators_stopped()
    cut = sync()
    if set(cut) != set(DBS) or any(type(v) is not int or not 0 < v < 2**64 for v in cut.values()):
        raise RuntimeError('incomplete planned cut')
    uploader_exit = graceful_stop(children['replicate'])
    return dict(cut=cut, trail_exit=trail_exit, uploader_exit=uploader_exit)


def serve(c):
    RUN.mkdir(exist_ok=True)
    lock = (RUN / 'node.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    writer = c['role'] == 'writer'
    if writer and not authority(c):
        raise ValueError('writer activation absent, stale, or for another epoch')
    data = BASE / 'depot/data'
    data.mkdir(exist_ok=True)
    if writer: validate_databases(data, c.get('bootstrap', False))
    if not writer and (data.is_symlink() or any(data.iterdir())):
        raise ValueError('standby restore directory is not empty; explicit clean rejoin required')
    children = {}
    readers = {}
    streams = []
    stopped = threading.Event()
    draining = threading.Event()
    quiesced = False
    state = dict(role=c['role'], epoch=c['epoch'], sampled_at=0, positions={}, refusals=['starting'])
    sticky = set()
    identities = {}
    def stop(*_): stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGUSR1, lambda *_: draining.set())
    def spawn(name, args):
        path = BASE / 'logs' / (str(time.time_ns()) + '-' + name + '.log')
        stream = path.open('xb'); streams.append(stream)
        env = dict(os.environ)
        if name == 'trail':
            env = {k: v for k, v in env.items() if not k.startswith('IDRIVE_')}
        children[name] = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, env=env)
        if name != 'trail': readers[name] = path.open()
    def status(): return public_status(state, time.time())
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ('/_hat/status', '/health'):
                value = status(); payload = json.dumps(value).encode()
                self.send_response(200 if self.path != '/health' or value['healthy'] else 503)
                self.send_header('Content-Type', 'application/json')
            elif self.path == '/':
                payload = Path('/opt/hat-demo/index.html').read_bytes()
                self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            else:
                self.send_error(404); return
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 4001), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        if writer:
            spawn('trail', [str(BIN/'trail'), '--depot', str(BASE/'depot'), 'run', '--address', '127.0.0.1:4000', '--stderr-logging'])
            deadline = time.monotonic() + 60
            while True:
                if stopped.wait(.2) or children['trail'].poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('TrailBase bootstrap failed; protected logs retained')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:4000/api/healthcheck', timeout=1) as r:
                        if r.status == 200: break
                except OSError: pass
            validate_databases(data)
            identities = {db: database_identity(data/(db+'.db')) for db in DBS}
            spawn('replicate', [str(BIN/'litestream'), 'replicate', '-config', '/etc/hat-demo/litestream.yml'])
        else:
            for db in DBS:
                spawn(db, [str(BIN/'litestream'), 'restore', '-config', '/etc/hat-demo/litestream.yml', '-f', '-follow-interval', '1s', '-o', str(data/(db+'.db')), str(data/(db+'.db'))])
        while not stopped.is_set():
            if quiesced:
                stopped.wait(1)
                continue
            if draining.is_set():
                request_path = Path('/run/hat-node-quiesce.json')
                s = regular_file(request_path)
                request = json.loads(request_path.read_text())
                if (not writer or not authority(c) or s.st_uid != 0 or s.st_mode & 0o022
                        or set(request) != {'operation', 'epoch', 'boot_id'}
                        or not re.fullmatch('[0-9a-f]{32}', request['operation'])
                        or request['epoch'] != c['epoch'] or request['boot_id'] != boot_id() or sticky):
                    raise RuntimeError('invalid quiesce authority or prior log refusal')
                state = dict(state, refusals=['quiescing'], phase='quiescing')
                def verify_mutators_stopped():
                    group = Path('/sys/fs/cgroup/system.slice/hat-demo.service/cgroup.procs')
                    if set(map(int, group.read_text().split())) != {os.getpid(), children['replicate'].pid}:
                        raise RuntimeError('unexpected process remains in node cgroup')
                def sync_cut():
                    cut = {}
                    for name in DBS:
                        database = str(data/(name+'.db'))
                        p = subprocess.run([str(BIN/'litestream'), 'sync', '-socket', str(RUN/'ls.sock'), '-wait', '-json', database], capture_output=True, timeout=30)
                        if p.returncode:
                            with (BASE/'logs/sync-errors.log').open('ab') as f: f.write(p.stderr)
                            raise RuntimeError('quiesced sync failed')
                        cut[name] = sync_position(json.loads(p.stdout), database)
                    return cut
                result = quiesce_owned(children, sync_cut, verify_mutators_stopped)
                for reader in readers.values():
                    tail = reader.read(4*1024*1024+1)
                    if len(tail) > 4*1024*1024 or any(log_bad(line) for line in tail.splitlines() if line.strip()):
                        raise RuntimeError('quiesce log refusal')
                state = dict(role=c['role'], epoch=c['epoch'], sampled_at=time.time(), positions=result['cut'],
                             refusals=['quiesced; no writer'], trailbase_running=False, processes={},
                             phase='quiesced', operation=request['operation'], boot_id=boot_id(), **result)
                quiesced = True
                continue
            reasons = []
            positions = {}
            if writer and not authority(c):
                raise RuntimeError('writer authority lost')
            for name, child in children.items():
                if child.poll() is not None:
                    raise RuntimeError('owned process exited: ' + name)
            for name, reader in readers.items():
                # Bound each read; partial lines are reconsidered at the next sample.
                for _ in range(10000):
                    offset = reader.tell(); line = reader.readline(65537)
                    if not line: break
                    if len(line) > 65536:
                        sticky.add(name + ': oversized log record'); break
                    if not line.endswith('\n'):
                        reader.seek(offset); break
                    if line.strip() and log_bad(line): sticky.add(name + ': error or unknown log; inspect protected log')
                else: sticky.add(name + ': log scan exceeded bound')
            if {p.stem for p in data.glob('*.db')} - set(DBS) - {'logs'}:
                sticky.add('unenrolled database')
            for db in DBS:
                try:
                    identity = database_identity(data/(db+'.db'))
                except (OSError, ValueError) as exc:
                    if db in identities:
                        raise RuntimeError('known database object invalid: ' + db) from exc
                    reasons.append(db + ': database not yet restored')
                    continue
                if db in identities and identity != identities[db]:
                    raise RuntimeError('database object replaced: ' + db)
                try:
                    if writer:
                        database = str(data/(db+'.db'))
                        p = subprocess.run([str(BIN/'litestream'), 'sync', '-socket', str(RUN/'ls.sock'), '-wait', '-json', database], capture_output=True, timeout=8)
                        if p.returncode:
                            with (BASE/'logs/sync-errors.log').open('ab') as f: f.write(p.stderr)
                            raise ValueError('sync failed')
                        positions[db] = sync_position(json.loads(p.stdout), database)
                    else:
                        sidecar = data/(db+'.db-txid')
                        regular_file(sidecar)
                        positions[db] = txid(sidecar.read_text().strip())
                    identities[db] = identity
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    reasons.append(db + ': position unconfirmed')
            state = dict(role=c['role'], epoch=c['epoch'], sampled_at=time.time(), positions=positions,
                         refusals=sorted(sticky) + reasons, trailbase_running=writer,
                         processes={name: child.poll() is None for name, child in children.items()})
            stopped.wait(3)
    finally:
        state = dict(state, refusals=['node stopping'])
        server.shutdown(); server.server_close()
        for child in children.values():
            if child.poll() is None: child.terminate()
        for child in children.values():
            try: child.wait(timeout=15)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
        for f in [*readers.values(), *streams]: f.close()
        lock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['serve', 'status', 'activate'])
    p.add_argument('--config', default='/etc/hat-demo/node.json')
    args = p.parse_args()
    if args.command == 'status':
        with urllib.request.urlopen('http://127.0.0.1:4001/_hat/status', timeout=5) as r:
            print(json.dumps(json.load(r), indent=2))
        return
    c = load_config(args.config)
    if args.command == 'activate': activate(c)
    else: serve(c)

if __name__ == '__main__': main()
