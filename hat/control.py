#!/usr/bin/env python3
"""D2 manual switchover controller; no automatic recovery or force bypass."""
import argparse
from contextlib import closing
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import pwd
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

PHASES = ('preflight', 'close_ingress', 'quiesce', 'fence', 'freeze',
          'compare', 'activate', 'baseline', 'route', 'verify')


def private_file(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077 or s.st_nlink != 1:
        raise ValueError('controller file must be private, owned, regular and singly linked')
    return s.st_dev, s.st_ino


class Journal:
    """One locked controller, committed intent before effects, no implicit recovery."""
    def __init__(self, root):
        self.root = Path(root)
        self.lock = None
        self.db = None
        self.operation = None
        self.next = 0
        self.pending = False

    def __enter__(self):
        try:
            s = self.root.lstat()
            if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077
                    or any(p.is_symlink() for p in self.root.parents)):
                raise ValueError('controller directory must be private, owned and not symlinked')
            self.directory_identity = s.st_dev, s.st_ino
            self.lock = os.open(self.root/'controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            private_file(self.root/'controller.lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root/'journal.db'
            for suffix in ('', '-journal', '-wal', '-shm'):
                candidate = self.root/('journal.db' + suffix)
                if candidate.exists() or candidate.is_symlink(): private_file(candidate)
            existing = path.exists()
            if existing:
                if not path.stat().st_size: raise ValueError('empty existing journal; reconciliation required')
            else:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
            self.db = sqlite3.connect(path, timeout=0)
            if existing:
                tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
                if tables != {'operations', 'steps'} or self.db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise ValueError('unrecognized or damaged journal; reconciliation required')
                self.db.execute('SELECT id,source,target,source_epoch,new_epoch,complete FROM operations LIMIT 0')
                self.db.execute('SELECT operation,position,phase,status,evidence FROM steps LIMIT 0')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=EXTRA')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                    source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
                    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
                CREATE UNIQUE INDEX IF NOT EXISTS one_unfinished ON operations(complete) WHERE complete=0;
                CREATE TABLE IF NOT EXISTS steps (
                    operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
                    phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
                    evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status));
            ''')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.database_identity = private_file(path)
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.db is not None: self.db.close(); self.db = None
        if self.lock is not None: os.close(self.lock); self.lock = None

    def check_authority(self):
        if self.lock is None or self.db is None: raise RuntimeError('controller is not locked')
        s = self.root.lstat(); owned = os.fstat(self.lock)
        if ((s.st_dev, s.st_ino) != self.directory_identity
                or private_file(self.root/'controller.lock') != (owned.st_dev, owned.st_ino)
                or private_file(self.root/'journal.db') != self.database_identity):
            raise RuntimeError('controller state or lock replaced; refuse further actions')

    def begin(self, source, target, source_epoch):
        self.check_authority()
        if source not in ('A', 'B') or target not in ('A', 'B') or source == target:
            raise ValueError('invalid demo transition')
        if not isinstance(source_epoch, str) or not re.fullmatch(r'd1-[a-z0-9-]+', source_epoch):
            raise ValueError('invalid source epoch')
        if self.operation or self.db.execute('SELECT id FROM operations WHERE complete=0').fetchone():
            raise RuntimeError('unfinished operation requires reconciliation; no retry or force')
        ident = uuid.uuid4().hex
        operation = dict(id=ident, source=source, target=target, source_epoch=source_epoch, new_epoch='d1-'+ident)
        with self.db:
            self.db.execute('INSERT INTO operations(id,source,target,source_epoch,new_epoch) VALUES(?,?,?,?,?)', tuple(operation.values()))
        self.operation = operation; self.next = 0; self.pending = False
        return dict(operation)

    def step(self, phase, action):
        self.check_authority()
        if (not self.operation or self.pending or self.next >= len(PHASES)
                or PHASES[self.next] != phase):
            raise RuntimeError('out-of-order or uncertain step; no retry')
        self.pending = True
        with self.db:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)', (self.operation['id'], self.next, phase, 'intent', '{}'))
        result = action()
        self.check_authority()
        evidence = json.dumps(result, allow_nan=False)
        with self.db:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)', (self.operation['id'], self.next, phase, 'done', evidence))
        self.next += 1; self.pending = False
        return result

    def _boundary(self, ident, position):
        self.check_authority()
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{32}',ident): raise ValueError('invalid operation')
        row=self.db.execute('SELECT id,source,target,source_epoch,new_epoch FROM operations WHERE id=? AND complete=0',(ident,)).fetchone()
        steps=self.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(PHASES[:position]) for s in ('intent','done')]+[(position,PHASES[position],'intent')]
        if not row or row[1:3]!=('A','B') or [s[:3] for s in steps]!=expected:
            raise RuntimeError('not the exact pending '+PHASES[position]+' boundary')
        return dict(zip(('id','source','target','source_epoch','new_epoch'),row)),{p:json.loads(e) for _,p,s,e in steps if s=='done'}

    def comparison_boundary(self, ident):
        return self._boundary(ident,5)

    def verification_boundary(self, ident):
        return self._boundary(ident,9)

    def accept_verification(self, ident, result):
        from transition import validate_cut
        operation,previous=self.verification_boundary(ident)
        validate_cut(result.get('positions'))
        proof=result.get('new_writes',{})
        if (result.get('writer')!='B' or result.get('epoch')!=operation['new_epoch']
                or proof.get('positions')!=result['positions'] or proof.get('auth_and_records')!='PASS'
                or any(result['positions'][db]<=pos for db,pos in previous['baseline']['positions'].items())):
            raise ValueError('verification lacks fresh-epoch new-write restore proof')
        with self.db:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,9,'verify','done',json.dumps(result,allow_nan=False)))
        self.operation=operation;self.next=10;self.pending=False

    def accept_comparison(self, ident, result):
        operation,previous=self.comparison_boundary(ident)
        frozen=previous['freeze']
        if (result.get('positions')!=frozen['cut'] or result.get('signature')!=frozen['signature']
                or result.get('auth_and_records')!='PASS'):
            raise ValueError('reconciled comparison does not match frozen cut')
        with self.db:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,5,'compare','done',json.dumps(result,allow_nan=False)))
        self.operation=operation;self.next=6;self.pending=False

    def finish(self):
        self.check_authority()
        if not self.operation or self.pending or self.next != len(PHASES):
            raise RuntimeError('cannot complete an unfinished transition')
        with self.db:
            self.db.execute('UPDATE operations SET complete=1 WHERE id=?', (self.operation['id'],))
        self.operation = None


def process_identity(pid):
    if type(pid) is not int or pid <= 0: return None
    try:
        fields=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        return fields[19] if fields[0] not in ('Z','X') else None
    except (OSError, IndexError): return None


def ingress_allowed(root, maintenance, permit, ingress, boot):
    """Boot/restart gate: unfinished routing needs its still-live original controller."""
    try:
        path=root/'journal.db'
        if not path.exists(): return not maintenance.exists()
        private_file(path)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            operation=db.execute('SELECT id,complete FROM operations ORDER BY rowid DESC LIMIT 1').fetchone()
            if not operation: return not maintenance.exists()
            ident,complete=operation
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            if complete:
                row=db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
                return not maintenance.exists() and row is not None and json.loads(row[0])['config_sha']==digest
            if (not maintenance.exists() or json.loads(maintenance.read_text())['operation']!=ident
                    or (root/ident/'failure.json').exists()
                    or not db.execute("SELECT 1 FROM steps WHERE operation=? AND phase='baseline' AND status='done'",(ident,)).fetchone()
                    or not db.execute("SELECT 1 FROM steps WHERE operation=? AND phase='route' AND status='intent'",(ident,)).fetchone()):
                return False
            private_file(permit); value=json.loads(permit.read_text())
            birth=process_identity(value['pid'])
            return (value['operation']==ident and value['boot_id']==boot and birth is not None
                    and value['birth']==birth and value['config_sha']==digest)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error): return False


def reconcile_existing(journal, maintenance, stop_ingress, ingress):
    from transition import atomic_json
    journal.check_authority()
    row=journal.db.execute('SELECT id FROM operations WHERE complete=0').fetchone()
    if row:
        try:
            if not maintenance.exists(): atomic_json(maintenance,{'operation':row[0]})
        finally: stop_ingress()
        raise RuntimeError('unfinished operation: ingress closed; explicit reconciliation required')
    completed=journal.db.execute('SELECT id,target FROM operations WHERE complete=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    if completed:
        ident,target=completed
        route=journal.db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
        if (target!='B' or not route or json.loads(route[0])['config_sha']!=hashlib.sha256(ingress.read_bytes()).hexdigest()):
            raise RuntimeError('completed route differs; reconciliation refused')
        if maintenance.exists():
            private_file(maintenance)
            if json.loads(maintenance.read_text())!={'operation':ident}: raise RuntimeError('maintenance belongs to another operation')
            maintenance.unlink()
            fd=os.open(maintenance.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        return True
    return False


def validate_fence(receipt, target, action, state, not_before):
    try:
        def stamp(value):
            dt = datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
            if dt.tzinfo is None: raise ValueError('fence time lacks timezone')
            return dt.timestamp()
        requested = stamp(receipt['request']['time']); completed = stamp(receipt['completion']['time'])
        observations = receipt['observations']; now = time.time()
        identity = observations[-1]['identity']
        addresses = {r[4][0] for r in socket.getaddrinfo(target['address'],None,socket.AF_INET,socket.SOCK_STREAM)}
        if (type(identity['instance_id']) is not int or identity['instance_id'] != target['instance_id']
                or identity['provider_label'] != target['provider_label'] or not addresses
                or not addresses <= set(identity['addresses'])):
            raise ValueError('provider-observed identity differs from target')
        if (receipt['target'] != target or receipt['action'] != action or receipt['state'] != state
                or not isinstance(receipt['request']['id'], str) or not receipt['request']['id']
                or not not_before <= requested <= completed <= now+5 or not 0 <= now-completed <= 300
                or len(observations) < 2 or observations[-1]['state'] != state
                or not completed <= stamp(observations[-1]['time']) <= now+5
                or any(not requested <= stamp(o['time']) <= now+5 for o in observations)
                or any(stamp(a['time']) > stamp(b['time']) for a,b in zip(observations,observations[1:]))):
            raise ValueError('unconfirmed fence')
    except (KeyError, IndexError, TypeError, AttributeError, OverflowError, OSError) as exc:
        raise ValueError('malformed fence receipt') from exc


def route_to_b(text):
    app = 'server a 127.0.0.1:14000 check'
    home = 'backend home\n    server a 127.0.0.1:14001 check'
    if text.count(app) != 1 or text.count(home) != 1: raise ValueError('unexpected existing route')
    return text.replace(app,'server b 127.0.0.1:14003 check').replace(home,'backend home\n    server b 127.0.0.1:14002 check')


def oracle_directory(area):
    area.mkdir(mode=0o750)
    area.chmod(0o750)  # mkdir's mode is otherwise reduced to 0700 by the controller umask.


def switchover(config, reconcile=None, verification_only=False):
    from transition import atomic_json, validate_cut
    from demo_smoke import smoke, verify_restore, request
    import node
    root = Path('/var/lib/hat-control')
    maintenance = Path('/etc/hat-control/maintenance')
    ingress = Path('/etc/hat-ingress/haproxy.cfg')
    with Journal(root) as journal:
        if not reconcile and reconcile_existing(journal,maintenance,lambda:subprocess.run(['systemctl','stop','hat-ingress.service'],check=True,timeout=60),ingress):
            subprocess.run(['systemctl','start','hat-ingress.service'],check=True,timeout=60)
            print('Existing completed transition to B reconciled; no new promotion performed.')
            return
        if reconcile:
            operation,previous=(journal.verification_boundary(reconcile) if verification_only else journal.comparison_boundary(reconcile))
            journal.next=9 if verification_only else 5
            if operation['source_epoch']!=config['epoch']:raise RuntimeError('source epoch changed')
        else: operation = journal.begin('A','B',config['epoch'])
        work = root/operation['id']
        if not reconcile:work.mkdir(mode=0o700)
        elif work.is_symlink() or not work.is_dir() or work.stat().st_uid!=0 or work.stat().st_mode & 0o077:
            raise ValueError('unsafe reconciliation directory')
        state = {'ingress_touched':bool(reconcile)}
        ledger = work/'client.jsonl'
        def command(args, data=None, timeout=180):
            journal.check_authority()
            prefix = work/str(time.time_ns())
            with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
                p = subprocess.run(args,input=data,stdout=out,stderr=err,timeout=timeout)
            journal.check_authority()
            if p.returncode: raise RuntimeError('command failed; protected stdout/stderr retained')
            if prefix.with_suffix('.stdout').stat().st_size > 4*1024*1024: raise RuntimeError('oversized command result')
            return prefix.with_suffix('.stdout').read_bytes()
        def remote(label, action, payload=None, epoch=None):
            boot = state.get(label,{}).get('boot_id')
            request = dict(action=action,operation=operation['id'],epoch=epoch or config['epoch'],boot_id=boot,payload=payload or {})
            host = config['nodes'][label]['address']
            return json.loads(command(['ssh','-i','/etc/hat-control/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                                       '-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/etc/hat-control/known_hosts',
                                       '-o','GlobalKnownHostsFile=/dev/null','root@'+host,'hat-node'],json.dumps(request).encode(),timeout=180))
        def fence(action, expected):
            path = Path('/etc/hat-control/target-fm1.json'); private_file(path)
            target = json.loads(path.read_text())
            if target != config['fence_target']: raise ValueError('fence target configuration changed')
            started = time.time()
            receipt = json.loads(command(['/root/.config/hat/m1-fence-linode',action,str(path)]))
            validate_fence(receipt,target,action,expected,started)
            if expected == 'offline':
                for _ in range(3):
                    try:
                        connection = socket.create_connection((config['nodes']['A']['address'],22),timeout=2)
                    except (ConnectionRefusedError, TimeoutError): pass
                    else:
                        connection.close(); raise RuntimeError('old writer remains reachable')
                    time.sleep(.2)
            return receipt
        def close_ingress():
            state['ingress_touched'] = True
            if not maintenance.exists(): atomic_json(maintenance, {'operation':operation['id']})
            command(['systemctl','stop','hat-ingress.service'])
            pid = command(['systemctl','show','-p','MainPID','--value','hat-ingress.service']).strip()
            if pid != b'0': raise RuntimeError('ingress still running')
            return {'closed':True}
        def oracle(phase, replica_config, positions, selected_ledger):
            validate_cut(positions)
            account = pwd.getpwnam('hat-oracle')
            area = Path('/var/lib/hat-oracle')/('d2-'+operation['id']+'-'+phase)
            oracle_directory(area); os.chown(area,0,account.pw_gid)
            output = area/'work'; output.mkdir(mode=0o700); os.chown(output,account.pw_uid,account.pw_gid)
            for name,content in [('replica.yml',replica_config),('positions.json',json.dumps(positions)),('ledger.jsonl',selected_ledger.read_text())]:
                path=area/name
                with path.open('x') as f:
                    os.fchmod(f.fileno(),0o640); os.fchown(f.fileno(),0,account.pw_gid); f.write(content); f.flush(); os.fsync(f.fileno())
            result = output/'report.json'
            command(['systemd-run','--unit=hat-d2-'+operation['id']+'-'+phase,'--wait','--collect','--pipe',
                     '--property=User=hat-oracle','--property=EnvironmentFile=/etc/hat-oracle/backup.env',
                     '--property=NoNewPrivileges=yes','--property=RuntimeMaxSec=240','--property=KillMode=control-group',
                     'python3','/opt/hat-oracle/restore_baseline.py','--root',str(output),'--config',str(area/'replica.yml'),
                     '--positions',str(area/'positions.json'),'--ledger',str(area/'ledger.jsonl'),
                     '--support','/var/lib/hat-oracle/support','--binaries','/opt/hat-oracle/bin','--result',str(result)],timeout=270)
            value = json.loads(result.read_text())
            if value['positions'] != positions or value['auth_and_records'] != 'PASS' or set(value['signature']) != set(node.DBS):
                raise RuntimeError('independent oracle refused')
            return value
        def preflight():
            if socket.gethostname() != config['hostname']: raise ValueError('wrong controller')
            if maintenance.exists(): raise RuntimeError('ingress maintenance already set')
            state['A'] = remote('A','probe'); state['B'] = remote('B','probe')
            for label,role in [('A','writer'),('B','standby')]:
                value=state[label]
                if value['config']['role'] != role or value['status']['epoch'] != config['epoch'] or value['status']['trailbase_running'] != (role=='writer'):
                    raise RuntimeError('unexpected node role or epoch')
            for field in ('binaries','support'):
                if state['A']['config'][field] != state['B']['config'][field]: raise RuntimeError('candidate release or identity differs')
            node.validate_support(Path('/var/lib/hat-oracle/support'),state['A']['config']['support'])
            for binary,digest in state['A']['config']['binaries'].items():
                if hashlib.sha256((Path('/opt/hat-oracle/bin')/binary).read_bytes()).hexdigest() != digest:
                    raise RuntimeError('oracle release differs')
            fence('inspect','running')
            route_to_b(ingress.read_text())
            shutil.copy2(ingress,work/'ingress-before.cfg')
            credentials = Path('/etc/hat-control/demo-login.json'); private_file(credentials)
            smoke('http://127.0.0.1:18080',json.loads(credentials.read_text()),ledger)
            history = Path('/etc/hat-control/history.jsonl'); private_file(history)
            with ledger.open('a') as f:
                for line in history.read_text().splitlines():
                    value=json.loads(line)
                    if value.get('event') == 'historical_auth':
                        code,_=request('http://127.0.0.1:18080','/api/auth/v1/refresh','POST',{'refresh_token':value['revoked_refresh']})
                        if code not in (400,401,403): raise ValueError('historical revoked token accepted by source')
                        code,_=request('http://127.0.0.1:18080','/api/auth/v1/refresh','POST',{'refresh_token':value['retained_refresh']})
                        if code not in (200,400,401,403): raise ValueError('historical retained token state unknown')
                        value['retained_expected']='accepted' if code==200 else 'denied'
                    elif value.get('event') != 'acknowledged': raise ValueError('invalid historical ledger entry')
                    f.write(json.dumps(value)+'\n')
                f.flush(); os.fsync(f.fileno())
            return {'source_boot':state['A']['boot_id'],'candidate_boot':state['B']['boot_id'],'identity':'matched'}
        def quiesce():
            value=remote('A','quiesce'); validate_cut(value['cut']); state['cut']=value['cut']; return value
        def power_off():
            state['fence']=fence('power-off','offline'); return state['fence']
        def freeze():
            state['frozen']=remote('B','freeze',{'cut':state['cut']}); return state['frozen']
        def compare():
            value=oracle('compare',state['A']['replica_config'],state['cut'],ledger)
            if value['signature'] != state['frozen']['signature']:
                state['frozen']=remote('B','restore',{'cut':state['cut']})
                if value['signature'] != state['frozen']['signature']: raise RuntimeError('fresh candidate differs from independent restore')
                value['candidate_source']='fresh-restore; rejected follower retained'
            else: value['candidate_source']='frozen-follower'
            state['comparison']=value; return value
        def activate():
            digest=hashlib.sha256(json.dumps(state['fence'],sort_keys=True).encode()).hexdigest()
            remote('B','prepare',dict(new_epoch=operation['new_epoch'],signature=state['comparison']['signature'],fence_digest=digest))
            value=remote('B','activate',epoch=operation['new_epoch'])
            state['new']=remote('B','probe',epoch=operation['new_epoch']); return value
        def baseline():
            state['baseline']=oracle('baseline',state['new']['replica_config'],state['new']['status']['positions'],ledger)
            return state['baseline']
        def start_ingress(digest):
            atomic_json(Path('/run/hat-control-route.json'),dict(operation=operation['id'],boot_id=node.boot_id(),
                        pid=os.getpid(),birth=process_identity(os.getpid()),config_sha=digest))
            command(['systemctl','start','hat-ingress.service'])
        def route():
            fence('inspect','offline')
            text=route_to_b((work/'ingress-before.cfg').read_text()); candidate=work/'haproxy.cfg'; candidate.write_text(text)
            command(['haproxy','-c','-f',str(candidate)])
            temp=ingress.with_suffix('.d2-pending')
            with temp.open('x') as f: os.fchmod(f.fileno(),0o644); f.write(text); f.flush(); os.fsync(f.fileno())
            os.replace(temp,ingress)
            fd=os.open(ingress.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            start_ingress(digest)
            return {'writer':'B','epoch':operation['new_epoch'],'config_sha':digest}
        def verify():
            verify_restore('http://127.0.0.1:18080',ledger)
            fresh=work/'new-writes.jsonl'
            smoke('http://127.0.0.1:18080',json.loads(Path('/etc/hat-control/demo-login.json').read_text()),fresh)
            deadline=time.monotonic()+90
            while True:
                value=remote('B','probe',epoch=operation['new_epoch'])
                if all(value['status']['positions'][db] > pos for db,pos in state['baseline']['positions'].items()): break
                if time.monotonic()>deadline: raise RuntimeError('new writes not confirmed published')
                time.sleep(1)
            evidence=oracle('new-writes',value['replica_config'],value['status']['positions'],fresh)
            return dict(writer='B',epoch=operation['new_epoch'],positions=value['status']['positions'],new_writes=evidence)
        actions=(preflight,close_ingress,quiesce,power_off,freeze,compare,activate,baseline,route,verify)
        try:
            if verification_only:
                private_file(maintenance)
                if json.loads(maintenance.read_text())!={'operation':operation['id']}:raise RuntimeError('maintenance identity changed')
                failure=work/'failure.json';private_file(failure)
                if json.loads(failure.read_text())!={'phase':'verify','error':'URLError'} or (work/'new-writes.jsonl').exists():
                    raise RuntimeError('not the approved pre-write HTTP failure boundary')
                intent=work/'verification-reconciliation.json'
                if intent.exists() or intent.is_symlink():raise RuntimeError('verification reconciliation already attempted')
                atomic_json(intent,dict(operation=reconcile,action='verification-only',failure_sha=hashlib.sha256(failure.read_bytes()).hexdigest()))
                close_ingress()
                fresh_fence=fence('inspect','offline')
                state['B']={'boot_id':previous['preflight']['candidate_boot']}
                current=remote('B','probe',epoch=operation['new_epoch'])
                if current['config']['role']!='writer' or not current['status']['trailbase_running']:raise RuntimeError('candidate writer changed')
                state['baseline']=previous['baseline']
                route_proof=previous['route'];digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
                if (route_proof['writer']!='B' or route_proof['epoch']!=operation['new_epoch'] or route_proof['config_sha']!=digest
                        or previous['baseline']['auth_and_records']!='PASS'):raise RuntimeError('recorded route/baseline changed')
                node.validate_support(Path('/var/lib/hat-oracle/support'),current['config']['support'])
                for binary,expected in current['config']['binaries'].items():
                    if hashlib.sha256((Path('/opt/hat-oracle/bin')/binary).read_bytes()).hexdigest()!=expected:raise RuntimeError('oracle release changed')
                oracle('verification-baseline',current['replica_config'],previous['baseline']['positions'],ledger)
                archived=work/'failure.before-verification.json'
                if archived.exists():raise RuntimeError('verification failure archive exists')
                failure.rename(archived)
                fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
                start_ingress(digest)
                value=verify();value['reconciliation_fence']=fresh_fence
                journal.accept_verification(reconcile,value)
            elif reconcile:
                private_file(maintenance)
                if json.loads(maintenance.read_text())!={'operation':operation['id']}:raise RuntimeError('maintenance identity changed')
                failure=work/'failure.json'; private_file(failure)
                if json.loads(failure.read_text()).get('phase')!='compare':raise RuntimeError('unexpected failed phase')
                intent=work/'reconciliation.json'
                if intent.exists() or intent.is_symlink():raise RuntimeError('reconciliation already attempted')
                atomic_json(intent,dict(operation=reconcile,action='accept-checked-comparison',failure_sha=hashlib.sha256(failure.read_bytes()).hexdigest()))
                close_ingress()
                state['fence']=previous['fence']; fresh_fence=fence('inspect','offline')
                state['B']={'boot_id':previous['preflight']['candidate_boot']}
                current=remote('B','inspect-frozen')
                if current['frozen']!=previous['freeze']:raise RuntimeError('candidate frozen state changed')
                node.validate_support(Path('/var/lib/hat-oracle/support'),current['config']['support'])
                for binary,digest in current['config']['binaries'].items():
                    if hashlib.sha256((Path('/opt/hat-oracle/bin')/binary).read_bytes()).hexdigest()!=digest:raise RuntimeError('oracle release changed')
                state['cut']=previous['freeze']['cut'];state['frozen']=previous['freeze']
                value=oracle('reconciled-compare',current['replica_config'],state['cut'],ledger)
                value['reconciliation_fence']=fresh_fence
                # Preserve the original failure; the ordinary gate must not ignore failures.
                archived=work/'failure.before-reconciliation.json'
                if archived.exists():raise RuntimeError('failure archive already exists')
                failure.rename(archived)
                fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
                journal.accept_comparison(reconcile,value)
                state['comparison']=value
                fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
            for phase,action in list(zip(PHASES,actions))[journal.next:]: journal.step(phase,action)
            journal.finish()
            maintenance.unlink()
            fd=os.open(maintenance.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        except BaseException as exc:
            failure_path=work/('reconciliation-failure-'+str(time.time_ns())+'.json' if reconcile and (work/'failure.json').exists() else 'failure.json')
            atomic_json(failure_path,{'phase':PHASES[min(journal.next,len(PHASES)-1)],'error':type(exc).__name__})
            if state['ingress_touched']: close_ingress()
            raise
        print('PASS: planned switchover to B; same URL, pre-cut records/auth retained, fresh-epoch writes remotely restored. A remains fenced.')


def main():
    parser=argparse.ArgumentParser(description='Manual D2 controller; no automatic recovery or force flag')
    parser.add_argument('command',choices=['switchover','ingress-check','reconcile-compare','reconcile-verify']); parser.add_argument('target',nargs='?')
    args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('root controller required')
    os.umask(0o077)
    if args.command=='ingress-check':
        import node
        raise SystemExit(0 if ingress_allowed(Path('/var/lib/hat-control'),Path('/etc/hat-control/maintenance'),
                         Path('/run/hat-control-route.json'),Path('/etc/hat-ingress/haproxy.cfg'),node.boot_id()) else 1)
    if args.command=='switchover' and args.target!='B': parser.error('switchover requires target B')
    if args.command in ('reconcile-compare','reconcile-verify') and not re.fullmatch('[0-9a-f]{32}',args.target or ''):parser.error('reconciliation requires exact operation ID')
    path=Path('/etc/hat-control/config.json'); private_file(path)
    config=json.loads(path.read_text())
    if config['hostname'] != socket.gethostname(): raise ValueError('wrong designated controller')
    switchover(config,reconcile=args.target if args.command in ('reconcile-compare','reconcile-verify') else None,
               verification_only=args.command=='reconcile-verify')

if __name__ == '__main__': main()
