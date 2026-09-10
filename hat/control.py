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
D3_PHASES = ('preflight', 'close_ingress', 'fence', 'select_cut', 'restore',
             'compare', 'activate', 'baseline', 'route', 'verify',
             'rejoin_boot', 'rejoin', 'verify_redundancy')
ROUTE_ENDPOINTS = {
    'A': {'writer':'127.0.0.1:14000', 'home':'127.0.0.1:14001'},
    'B': {'writer':'127.0.0.1:14003', 'home':'127.0.0.1:14002'},
}


def phase_plan(source, target):
    try: return {('A','B'):PHASES, ('B','A'):D3_PHASES}[(source,target)]
    except KeyError as exc: raise ValueError('invalid demo transition') from exc


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
        phase_plan(source,target)
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
        row=(self.db.execute('SELECT source,target,complete FROM operations WHERE id=?',(self.operation['id'],)).fetchone()
             if self.operation else None)
        plan=phase_plan(*row[:2]) if row and not row[2] else ()
        if (not self.operation or not row or row[:2]!=(self.operation['source'],self.operation['target'])
                or self.pending or self.next >= len(plan) or plan[self.next] != phase):
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

    def _boundary(self, ident, position, direction=('A','B')):
        self.check_authority()
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{32}',ident): raise ValueError('invalid operation')
        row=self.db.execute('SELECT id,source,target,source_epoch,new_epoch FROM operations WHERE id=? AND complete=0',(ident,)).fetchone()
        if not row or row[1:3] != direction: raise RuntimeError('operation direction or identity differs')
        plan=phase_plan(*row[1:3])
        if not 0 <= position < len(plan): raise RuntimeError('invalid operation boundary')
        steps=self.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(plan[:position]) for s in ('intent','done')]+[(position,plan[position],'intent')]
        if [s[:3] for s in steps]!=expected:
            raise RuntimeError('not the exact pending '+plan[position]+' boundary')
        try: evidence={p:json.loads(e) for _,p,s,e in steps if s=='done'}
        except (TypeError,ValueError) as exc: raise RuntimeError('malformed operation evidence') from exc
        return dict(zip(('id','source','target','source_epoch','new_epoch'),row)),evidence

    def comparison_boundary(self, ident):
        return self._boundary(ident,5)

    def verification_boundary(self, ident):
        return self._boundary(ident,9)

    def continue_rejoin(self, ident, boot_done=False):
        self.check_authority()
        if self.operation: raise RuntimeError('journal already has an active operation')
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{32}',ident): raise ValueError('invalid operation')
        row=self.db.execute('SELECT id,source,target,source_epoch,new_epoch FROM operations WHERE id=? AND complete=0',(ident,)).fetchone()
        steps=self.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(D3_PHASES[:10]) for s in ('intent','done')]
        if boot_done: expected += [(10,'rejoin_boot',s) for s in ('intent','done')]
        if (not row or row[1:3]!=('B','A') or [s[:3] for s in steps]!=expected
                or any(e!='{}' for _,_,status,e in steps if status=='intent')
                or (self.root/ident/'failure.json').exists() or (self.root/ident/'failure.json').is_symlink()):
            raise RuntimeError('not the exact unused D3 rejoin boundary')
        try: previous={p:json.loads(e) for _,p,s,e in steps if s=='done'}
        except (TypeError,ValueError) as exc: raise RuntimeError('malformed operation evidence') from exc
        operation=dict(zip(('id','source','target','source_epoch','new_epoch'),row))
        _validate_d3_proof(operation,previous)
        if boot_done:
            marker=self.root/ident/'reconciliation-rejoin-boot.json'
            archive=self.root/ident/'failure.before-reconciliation-rejoin-boot.json'
            private_file(marker);private_file(archive)
            proof=json.loads(marker.read_text())
            if (proof.get('operation')!=ident or proof.get('action')!='reconcile-rejoin-boot'
                    or proof.get('failure_sha')!=hashlib.sha256(archive.read_bytes()).hexdigest()):
                raise RuntimeError('reconciled boot provenance differs')
        self.operation=operation;self.next=11 if boot_done else 10;self.pending=False
        return dict(operation),previous

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
        row=(self.db.execute('SELECT source,target,complete FROM operations WHERE id=?',(self.operation['id'],)).fetchone()
             if self.operation else None)
        plan=phase_plan(*row[:2]) if row and not row[2] else ()
        steps=(self.db.execute('SELECT position,phase,status FROM steps WHERE operation=? ORDER BY rowid',(self.operation['id'],)).fetchall()
               if self.operation else [])
        expected=[(i,phase,status) for i,phase in enumerate(plan) for status in ('intent','done')]
        if (not self.operation or not row or row[:2]!=(self.operation['source'],self.operation['target'])
                or self.pending or self.next != len(plan) or steps!=expected):
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


def _validate_d3_proof(operation, evidence, verified=True):
    """Validate the D3 producer contract using existing oracle report shapes.

    select_cut.positions is the old-epoch cut. restore retains the node's cut/signature
    result; it does NOT assert an HTTP/auth check. compare, baseline, and verify.new_writes
    carry independent oracle auth/record proof. Baseline binds the reserved new epoch;
    its TXIDs are never compared numerically with the old-epoch cut.
    """
    from transition import validate_cut
    try:
        if not isinstance(evidence,dict) or operation['source']!='B' or operation['target']!='A':
            raise ValueError('invalid D3 operation proof')
        selected=evidence['select_cut']['positions'];validate_cut(selected)

        def report(value, auth_required=True, position_key='positions'):
            if not isinstance(value,dict): raise ValueError('invalid D3 restore report')
            positions=value[position_key];signature=value['signature'];validate_cut(positions)
            if (not isinstance(signature,dict) or set(signature)!=set(positions)
                    or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in signature.values())
                    or (auth_required and value.get('auth_and_records')!='PASS')):
                raise ValueError('invalid D3 restore report')
            return value

        restored=report(evidence['restore'],auth_required=False,position_key='cut');compared=report(evidence['compare']);baseline=report(evidence['baseline'])
        if (restored['cut']!=selected or compared['positions']!=selected
                or restored['signature']!=compared['signature']
                or baseline.get('epoch')!=operation['new_epoch']):
            raise ValueError('D3 selected cut, restore, comparison, or baseline differs')
        if not verified: return
        route=evidence['route'];verification=evidence['verify'];new_writes=verification['new_writes']
        if (not isinstance(route,dict) or route.get('writer')!='A' or route.get('epoch')!=operation['new_epoch']
                or not re.fullmatch('[0-9a-f]{64}',route.get('config_sha',''))
                or not isinstance(verification,dict) or verification.get('writer')!='A'
                or verification.get('epoch')!=operation['new_epoch'] or not isinstance(new_writes,dict)):
            raise ValueError('D3 route or fresh-epoch verification differs')
        new_writes=report(new_writes);positions=new_writes['positions']
        if (verification.get('positions')!=positions
                or any(positions[db]<=position for db,position in baseline['positions'].items())):
            raise ValueError('D3 new-write restore proof is not beyond baseline')
    except (KeyError,TypeError,AttributeError,ValueError) as exc:
        raise RuntimeError('D3 recovery proof differs or is malformed') from exc


def _d3_serving_state(db, ident, digest, failure):
    row=db.execute('SELECT source,target,new_epoch,complete FROM operations WHERE id=?',(ident,)).fetchone()
    if not row or row[:2]!=('B','A') or row[3]: return False
    steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
    base=[(i,p,s) for i,p in enumerate(D3_PHASES[:10]) for s in ('intent','done')]
    tail=[(i,p,s) for i,p in enumerate(D3_PHASES[10:],10) for s in ('intent','done')]
    if len(steps)<len(base) or len(steps)>len(base)+len(tail) or [s[:3] for s in steps] != base+tail[:len(steps)-len(base)]:
        return False
    if any(e!='{}' for _,_,status,e in steps if status=='intent'): return False
    try:
        evidence={phase:json.loads(value) for _,phase,status,value in steps if status=='done'}
        _validate_d3_proof({'id':ident,'source':row[0],'target':row[1],'new_epoch':row[2]},evidence)
    except (TypeError,ValueError,RuntimeError): return False
    route=evidence['route']
    if set(route)!={'writer','epoch','config_sha'} or route['config_sha']!=digest: return False
    if failure.exists() or failure.is_symlink():
        if (len(steps)-len(base))%2 != 1: return False
        try: private_file(failure); value=json.loads(failure.read_text())
        except (OSError,ValueError,TypeError): return False
        if (not isinstance(value,dict) or set(value)!={'phase','error'} or value['phase']!=steps[-1][1]
                or value['phase'] not in D3_PHASES[10:] or not isinstance(value['error'],str)
                or not re.fullmatch('[A-Za-z][A-Za-z0-9_]*',value['error'])):
            return False
    return True


def _exact_route(value, writer, epoch, digest):
    return (isinstance(value, dict) and set(value)=={'writer','epoch','config_sha'}
            and value == {'writer':writer,'epoch':epoch,'config_sha':digest})


def current_writer(journal, ingress):
    """Return writer authority only from a complete operation and its exact live route."""
    journal.check_authority()
    if journal.db.execute('SELECT 1 FROM operations WHERE complete=0').fetchone():
        raise RuntimeError('unfinished operation has no current writer authority')
    row=journal.db.execute('SELECT id,source,target,new_epoch FROM operations WHERE complete=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    if not row: raise RuntimeError('no completed writer authority')
    ident,source,target,epoch=row;plan=phase_plan(source,target)
    steps=journal.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
    expected=[(i,p,s) for i,p in enumerate(plan) for s in ('intent','done')]
    if [step[:3] for step in steps]!=expected or any(e!='{}' for _,_,status,e in steps if status=='intent'):
        raise RuntimeError('completed operation journal differs')
    try: route=json.loads(next(e for _,phase,status,e in steps if phase=='route' and status=='done'))
    except (StopIteration,TypeError,ValueError) as exc: raise RuntimeError('completed route evidence is malformed') from exc
    digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
    if not _exact_route(route,target,epoch,digest):
        raise RuntimeError('completed route differs from writer authority')
    return {'operation':ident,'writer':target,'epoch':epoch}


def ingress_allowed(root, maintenance, permit, ingress, boot):
    """Boot/restart gate for exact completed, live D2 route, or verified D3 route."""
    try:
        marker_present=maintenance.exists() or maintenance.is_symlink()
        if marker_present: private_file(maintenance)
        path=root/'journal.db'
        if not path.exists(): return not marker_present
        private_file(path)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            operation=db.execute('SELECT id,source,target,complete,new_epoch FROM operations ORDER BY rowid DESC LIMIT 1').fetchone()
            if not operation: return not marker_present
            ident,source,target,complete,epoch=operation
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            if complete:
                row=db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
                return (not marker_present and row is not None
                        and _exact_route(json.loads(row[0]),target,epoch,digest))
            if (source,target)==('B','A'):
                if not re.fullmatch('[0-9a-f]{32}',ident) or not marker_present: return False
                if json.loads(maintenance.read_text())!={'operation':ident}: return False
                failure=root/ident/'failure.json'
                if _d3_serving_state(db,ident,digest,failure): return True
                steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
                route_pending=[(i,p,s) for i,p in enumerate(D3_PHASES[:8]) for s in ('intent','done')]+[(8,'route','intent')]
                verify_pending=[(i,p,s) for i,p in enumerate(D3_PHASES[:9]) for s in ('intent','done')]+[(9,'verify','intent')]
                if ([step[:3] for step in steps] not in (route_pending,verify_pending)
                        or any(value!='{}' for _,_,status,value in steps if status=='intent')
                        or failure.exists() or failure.is_symlink()):
                    return False
                evidence={phase:json.loads(value) for _,phase,status,value in steps if status=='done'}
                _validate_d3_proof({'id':ident,'source':source,'target':target,'new_epoch':epoch},evidence,False)
                if [step[:3] for step in steps]==verify_pending:
                    route=evidence.get('route',{})
                    if (set(route)!={'writer','epoch','config_sha'} or route.get('writer')!='A'
                            or route.get('epoch')!=epoch or route.get('config_sha')!=digest): return False
                private_file(permit);value=json.loads(permit.read_text())
                if not isinstance(value,dict) or set(value)!={'operation','boot_id','pid','birth','config_sha'}: return False
                birth=process_identity(value['pid'])
                return (value['operation']==ident and value['boot_id']==boot and birth is not None
                        and value['birth']==birth and value['config_sha']==digest)
            expected=[(i,p,s) for i,p in enumerate(PHASES[:8]) for s in ('intent','done')]+[(8,'route','intent')]
            steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
            if (not marker_present or json.loads(maintenance.read_text())['operation']!=ident
                    or (root/ident/'failure.json').exists()
                    or [step[:3] for step in steps] != expected
                    or any(value!='{}' for _,_,status,value in steps if status=='intent')):
                return False
            private_file(permit); value=json.loads(permit.read_text())
            birth=process_identity(value['pid'])
            return (value['operation']==ident and value['boot_id']==boot and birth is not None
                    and value['birth']==birth and value['config_sha']==digest)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error): return False


def reconcile_existing(journal, maintenance, stop_ingress, ingress):
    from transition import atomic_json
    journal.check_authority()
    row=journal.db.execute('SELECT id FROM operations WHERE complete=0').fetchone()
    if row:
        ident=row[0];safe=False
        try:
            if maintenance.exists():
                private_file(maintenance)
                safe=(json.loads(maintenance.read_text())=={'operation':ident}
                      and _d3_serving_state(journal.db,ident,hashlib.sha256(ingress.read_bytes()).hexdigest(),journal.root/ident/'failure.json'))
        except (OSError,ValueError,KeyError,TypeError,sqlite3.Error): pass
        if safe: raise RuntimeError('verified D3 operation awaits explicit rejoin; safe A route preserved')
        try:
            if not maintenance.exists(): atomic_json(maintenance,{'operation':ident})
        finally: stop_ingress()
        raise RuntimeError('unfinished operation: ingress closed; explicit reconciliation required')
    completed=journal.db.execute('SELECT id,target FROM operations WHERE complete=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    if completed:
        ident,target=completed
        route=journal.db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
        digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
        try:
            route_value=json.loads(route[0]) if route else None
            epoch=journal.db.execute('SELECT new_epoch FROM operations WHERE id=?',(ident,)).fetchone()[0]
        except (TypeError,ValueError,sqlite3.Error) as exc:
            raise RuntimeError('completed route differs; reconciliation refused') from exc
        if (target!='B' or not _exact_route(route_value,target,epoch,digest)):
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


def route_to(text, source, target, endpoints):
    phase_plan(source,target)
    if set(endpoints)!= {'A','B'}: raise ValueError('route endpoints must be exact A/B configuration')
    for value in endpoints.values():
        if not isinstance(value,dict) or set(value)!={'writer','home'}:
            raise ValueError('invalid loopback route endpoints')
        for endpoint in value.values():
            match=re.fullmatch(r'127\.0\.0\.1:([1-9][0-9]{0,4})',endpoint) if isinstance(endpoint,str) else None
            if not match or int(match.group(1))>65535: raise ValueError('invalid loopback route endpoints')
    old=(f'server {source.lower()} {endpoints[source]["writer"]} check',
         f'backend home\n    server {source.lower()} {endpoints[source]["home"]} check')
    new=(f'server {target.lower()} {endpoints[target]["writer"]} check',
         f'backend home\n    server {target.lower()} {endpoints[target]["home"]} check')
    if any(text.count(value)!=1 for value in old) or any(value in text for value in new):
        raise ValueError('unexpected existing route')
    return text.replace(old[0],new[0]).replace(old[1],new[1])


def route_to_b(text):
    return route_to(text,'A','B',ROUTE_ENDPOINTS)


def oracle_directory(area):
    area.mkdir(mode=0o750)
    area.chmod(0o750)  # mkdir's mode is otherwise reduced to 0700 by the controller umask.


class ControlIO:
    """Shared command, node RPC, fence, ingress, and oracle I/O for a transition."""
    SSH_FLAGS = ('-i', '/etc/hat-control/id_ed25519', '-o', 'IdentitiesOnly=yes',
                 '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                 '-o', 'StrictHostKeyChecking=yes',
                 '-o', 'UserKnownHostsFile=/etc/hat-control/known_hosts',
                 '-o', 'GlobalKnownHostsFile=/dev/null')
    _TARGET_FIELDS = {'node', 'instance_id', 'provider_label', 'address', 'host_key'}

    def __init__(self, journal, config, operation, work, state,
                 maintenance=Path('/etc/hat-control/maintenance'),
                 ingress=Path('/etc/hat-ingress/haproxy.cfg')):
        self.journal = journal
        self.config = config
        self.operation = operation
        self.work = Path(work)
        self.state = state
        self.maintenance = Path(maintenance)
        self.ingress = Path(ingress)

    def _durable_json(self, path, value):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'), allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def command(self, args, data=None, timeout=180):
        self.journal.check_authority()
        argv = list(args)
        prefix = self.work / str(time.time_ns())
        intent = prefix.with_suffix('.intent.json')
        self._durable_json(intent, {'argv': argv})
        stdout = prefix.with_suffix('.stdout')
        stderr = prefix.with_suffix('.stderr')
        out_fd = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        err_fd = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out_fd, 'wb') as out, os.fdopen(err_fd, 'wb') as err:
            try:
                process = subprocess.run(argv, input=data, stdout=out, stderr=err, timeout=timeout)
            except subprocess.TimeoutExpired:
                self.journal.check_authority()
                self._durable_json(prefix.with_suffix('.outcome.json'),
                                   {'argv': argv, 'returncode': None, 'uncertain': True})
                raise
            except BaseException:
                self.journal.check_authority()
                self._durable_json(prefix.with_suffix('.outcome.json'),
                                   {'argv': argv, 'returncode': None, 'uncertain': False})
                raise
        self.journal.check_authority()
        self._durable_json(prefix.with_suffix('.outcome.json'),
                           {'argv': argv, 'returncode': process.returncode, 'uncertain': False})
        if process.returncode:
            raise RuntimeError('command failed; protected stdout/stderr retained')
        if stdout.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('oversized command result')
        return stdout.read_bytes()

    def remote(self, label, action, payload=None, epoch=None, timeout=180):
        node = self.config['nodes'][label]
        request = dict(action=action, operation=self.operation['id'],
                       epoch=(self.operation['source_epoch'] if epoch is None else epoch),
                       boot_id=self.state.get(label, {}).get('boot_id'), payload=payload or {})
        host = node['address']
        argv = ['ssh', *self.SSH_FLAGS, 'root@' + host, 'hat-node']
        return json.loads(self.command(argv, json.dumps(request).encode(), timeout=timeout))

    def wait_reachable(self, label, timeout=90):
        """Bounded read-only readiness check against the pinned node address."""
        address = self.config['nodes'][label]['address']
        deadline = time.monotonic() + timeout
        while True:
            self.journal.check_authority()
            try:
                connection = socket.create_connection((address, 22), timeout=min(2, max(.1, deadline-time.monotonic())))
            except (ConnectionRefusedError, TimeoutError, OSError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('node SSH readiness was not observed')
                time.sleep(.2)
            else:
                connection.close()
                return {'label': label, 'address': address, 'port': 22}

    def _fence_target(self, label):
        if label == 'A':
            path = Path('/etc/hat-control/target-fm1.json')
            trustedpin = self.config['fence_target']
        elif label == 'B':
            path = Path('/etc/hat-control/target-fm2.json')
            targets = self.config.get('fence_targets')
            if not isinstance(targets, dict) or 'B' not in targets:
                raise ValueError('explicit B fence target trusted pin required')
            trustedpin = targets['B']
            if isinstance(trustedpin, dict) and 'trustedpin' in trustedpin:
                trustedpin = trustedpin['trustedpin']
        else:
            raise ValueError('invalid fence label')
        if not isinstance(trustedpin, dict) or set(trustedpin) != self._TARGET_FIELDS:
            raise ValueError('fence target must have exact identity shape')
        if trustedpin['node'] != ('fm1' if label == 'A' else 'fm2'):
            raise ValueError('fence target node does not match label')
        try:
            configured_address = self.config['nodes'][label]['address']
        except (KeyError, TypeError) as exc:
            raise ValueError('configured logical node is missing') from exc
        if trustedpin['address'] != configured_address:
            raise ValueError('fence target address does not match logical node')
        private_file(path)
        target = json.loads(path.read_text())
        if target != trustedpin:
            raise ValueError('fence target configuration changed')
        return path, target

    def fence(self, action, expected, label='A'):
        path, target = self._fence_target(label)
        started = time.time()
        receipt = json.loads(self.command(['/root/.config/hat/m1-fence-linode', action, str(path)]))
        validate_fence(receipt, target, action, expected, started)
        if expected == 'offline':
            address = self.config['nodes'][label]['address']
            for _ in range(3):
                try:
                    connection = socket.create_connection((address, 22), timeout=2)
                except (ConnectionRefusedError, TimeoutError):
                    pass
                else:
                    connection.close()
                    raise RuntimeError('old writer remains reachable')
                time.sleep(.2)
        return receipt

    def close_ingress(self):
        from transition import atomic_json
        self.state['ingress_touched'] = True
        if not self.maintenance.exists():
            atomic_json(self.maintenance, {'operation': self.operation['id']})
        self.command(['systemctl', 'stop', 'hat-ingress.service'])
        pid = self.command(['systemctl', 'show', '-p', 'MainPID', '--value', 'hat-ingress.service']).strip()
        if pid != b'0':
            raise RuntimeError('ingress still running')
        return {'closed': True}

    def producer_stopped(self, unit, cgroup):
        """Prove producer death from its loaded systemd unit and fixed cgroup, not its ledger marker."""
        match = re.fullmatch(r'hat-d3-client-[0-9a-f]{32}\.service', unit) if isinstance(unit, str) else None
        path = Path(cgroup) if isinstance(cgroup, str) else None
        if not match or path != Path('/sys/fs/cgroup/system.slice') / unit:
            raise ValueError('invalid fixed producer unit or cgroup')
        raw = self.command(['systemctl', 'show', '--property=LoadState', '--property=MainPID',
                            '--property=ActiveState', '--property=SubState', unit]).decode()
        fields = {}
        for line in raw.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key in fields: raise RuntimeError('producer unit state is malformed')
            fields[key] = value
        if (set(fields) != {'LoadState', 'MainPID', 'ActiveState', 'SubState'}
                or fields['LoadState'] != 'loaded' or fields['MainPID'] != '0'
                or fields['ActiveState'] not in ('inactive', 'failed')):
            raise RuntimeError('fault producer is live or not a known stopped unit')
        cgroup_state = 'absent'
        if path.exists() or path.is_symlink():
            s = path.lstat()
            if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):
                raise RuntimeError('producer cgroup is unsafe')
            procs = path / 'cgroup.procs'
            if procs.is_symlink() or not procs.is_file() or procs.read_text().strip():
                raise RuntimeError('fault producer cgroup is not empty')
            cgroup_state = 'empty'
        return {'unit': unit, 'load_state': 'loaded', 'main_pid': 0,
                'active_state': fields['ActiveState'], 'sub_state': fields['SubState'],
                'cgroup': cgroup_state}

    def select_cut(self, replica_config, minimum):
        """Run and retain all three pinned native dry-run plans under the oracle account."""
        from transition import validate_cut
        from recovery import restore_endpoint
        import node
        validate_cut(minimum)
        account = pwd.getpwnam('hat-oracle')
        area = Path('/var/lib/hat-oracle') / ('d3-' + self.operation['id'] + '-select-cut')
        oracle_directory(area); os.chown(area, 0, account.pw_gid)
        output = area / 'work'; output.mkdir(mode=0o700); os.chown(output, account.pw_uid, account.pw_gid)
        config = area / 'replica.yml'
        with config.open('x') as stream:
            os.fchmod(stream.fileno(), 0o640); os.fchown(stream.fileno(), 0, account.pw_gid)
            stream.write(replica_config); stream.flush(); os.fsync(stream.fileno())
        plans, positions = {}, {}
        for db in node.DBS:
            source = '/var/lib/hat-demo/depot/data/' + db + '.db'
            target = str(output / (db + '.db'))
            unit = 'hat-d3-' + self.operation['id'] + '-plan-' + db
            raw = self.command(['systemd-run', '--unit=' + unit, '--wait', '--collect', '--pipe',
                                '--property=User=hat-oracle', '--property=EnvironmentFile=/etc/hat-oracle/backup.env',
                                '--property=NoNewPrivileges=yes', '--property=RuntimeMaxSec=90',
                                '--property=KillMode=control-group', '/opt/hat-oracle/bin/litestream',
                                'restore', '-config', str(config), '-dry-run', '-json', '-o', target, source],
                               timeout=120)
            if Path(target).exists() or Path(target).is_symlink():
                raise RuntimeError('dry-run restore created an output file')
            plan = json.loads(raw)
            positions[db] = restore_endpoint(plan, source, target, minimum[db])
            plans[db] = plan
            self._durable_json(self.work / ('restore-plan-' + db + '.json'), plan)
        return {'positions': positions, 'plans': plans}

    def oracle(self, phase, replica_config, positions, selected_ledger,
               fault_ledger=None, source_epoch=None):
        from transition import validate_cut
        import node
        validate_cut(positions)
        if (fault_ledger is None) != (source_epoch is None):
            raise ValueError('fault ledger and source epoch must be supplied together')
        account = pwd.getpwnam('hat-oracle')
        prefix = 'd2' if (self.operation['source'], self.operation['target']) == ('A', 'B') else 'd3'
        area = Path('/var/lib/hat-oracle') / (prefix + '-' + self.operation['id'] + '-' + phase)
        oracle_directory(area)
        os.chown(area, 0, account.pw_gid)
        output = area / 'work'
        output.mkdir(mode=0o700)
        os.chown(output, account.pw_uid, account.pw_gid)
        files = [('replica.yml', replica_config), ('positions.json', json.dumps(positions)),
                 ('ledger.jsonl', selected_ledger.read_text())]
        for name, content in files:
            path = area / name
            with path.open('x') as stream:
                os.fchmod(stream.fileno(), 0o640)
                os.fchown(stream.fileno(), 0, account.pw_gid)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        oracle_fault = None
        if fault_ledger is not None:
            oracle_fault = output / 'fault-ledger.jsonl'
            with oracle_fault.open('x') as stream:
                os.fchmod(stream.fileno(), 0o600)
                os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
                stream.write(Path(fault_ledger).read_text())
                stream.flush(); os.fsync(stream.fileno())
        result = output / 'report.json'
        unit = 'hat-' + prefix + '-' + self.operation['id'] + '-' + phase
        argv = ['systemd-run', '--unit=' + unit, '--wait', '--collect', '--pipe',
                '--property=User=hat-oracle', '--property=EnvironmentFile=/etc/hat-oracle/backup.env',
                '--property=NoNewPrivileges=yes', '--property=RuntimeMaxSec=240', '--property=KillMode=control-group',
                'python3', '/opt/hat-oracle/restore_baseline.py', '--root', str(output),
                '--config', str(area / 'replica.yml'), '--positions', str(area / 'positions.json'),
                '--ledger', str(area / 'ledger.jsonl'), '--support', '/var/lib/hat-oracle/support',
                '--binaries', '/opt/hat-oracle/bin', '--result', str(result)]
        if fault_ledger is not None:
            argv += ['--fault-ledger', str(oracle_fault), '--source-epoch', source_epoch]
        self.command(argv, timeout=270)
        value = json.loads(result.read_text())
        if value['positions'] != positions or value['auth_and_records'] != 'PASS' or set(value['signature']) != set(node.DBS):
            raise RuntimeError('independent oracle refused')
        return value

    def verify_url(self, ledger):
        from demo_smoke import verify_restore
        verify_restore('http://127.0.0.1:18080', ledger)

    def smoke_url(self, credentials, ledger):
        from demo_smoke import smoke
        smoke('http://127.0.0.1:18080', json.loads(Path(credentials).read_text()), ledger)

    def start_ingress(self, digest):
        from transition import atomic_json
        import node
        atomic_json(Path('/run/hat-control-route.json'),
                    dict(operation=self.operation['id'], boot_id=node.boot_id(), pid=os.getpid(),
                         birth=process_identity(os.getpid()), config_sha=digest))
        self.command(['systemctl', 'start', 'hat-ingress.service'])


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
        io = ControlIO(journal, config, operation, work, state, maintenance, ingress)
        command = io.command
        remote = io.remote
        fence = io.fence
        close_ingress = io.close_ingress
        oracle = io.oracle
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
        start_ingress = io.start_ingress
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


def rejoin(config, operation_id, *, root=Path('/var/lib/hat-control'), ingress=Path('/etc/hat-ingress/haproxy.cfg'),
           maintenance=Path('/etc/hat-control/maintenance'), io_factory=None, boot_done=False, _journal=None):
    """Continue exactly one verified recovery at its durable rejoin boundary."""
    import node
    import transition
    root, ingress, maintenance = map(Path, (root, ingress, maintenance))
    if io_factory is None: io_factory = ControlIO
    from contextlib import nullcontext
    with (Journal(root) if _journal is None else nullcontext(_journal)) as journal:
        operation, previous = journal.continue_rejoin(operation_id, boot_done=boot_done)
        route = previous['route']
        work = root / operation_id
        state = {'A': {}, 'ingress_touched': False}
        io = io_factory(journal, config, operation, work, state, maintenance, ingress)
        activated_probe = previous.get('activate', {}).get('probe', {})
        expected_config = activated_probe.get('config', {})
        activated_boot = activated_probe.get('boot_id')
        candidate_boot = previous.get('preflight', {}).get('candidate_boot')
        expected_a_boot = activated_boot or candidate_boot
        old_b_boot = previous['preflight'].get('source_boot')

        def writer_probe(value, boot):
            config_value, status = value.get('config', {}), value.get('status', {})
            positions = status.get('positions')
            transition.validate_cut(positions)
            if (value.get('boot_id') != boot or config_value.get('role') != 'writer'
                    or config_value.get('epoch') != operation['new_epoch']
                    or config_value.get('binaries') != expected_config.get('binaries')
                    or config_value.get('support') != expected_config.get('support')
                    or status.get('epoch') != operation['new_epoch'] or status.get('healthy') is not True
                    or status.get('trailbase_running') is not True):
                raise RuntimeError('A is not the retained healthy same-epoch writer')
            return positions

        def boot():
            if boot_done:
                return previous['rejoin_boot']
            if (activated_boot is not None and candidate_boot is not None
                    and activated_boot != candidate_boot):
                raise RuntimeError('retained A boot evidence differs')
            if (route.get('writer') != 'A' or route.get('epoch') != operation['new_epoch']
                    or hashlib.sha256(ingress.read_bytes()).hexdigest() != route.get('config_sha')):
                raise RuntimeError('verified A route is not current')
            if not isinstance(expected_a_boot, str) or not expected_a_boot:
                raise RuntimeError('retained A boot evidence is unavailable')
            probe = io.remote('A', 'probe', epoch=operation['new_epoch'])
            state['A'] = {'boot_id': expected_a_boot, 'positions': writer_probe(probe, expected_a_boot)}
            receipt = io.fence('power-on', 'running', label='B')
            if not isinstance(receipt, dict) or receipt.get('action') != 'power-on' or receipt.get('state') != 'running':
                raise RuntimeError('power-on receipt is not pinned')
            readiness = io.wait_reachable('B', timeout=90)
            cold = io.remote('B', 'inspect-cold', epoch=operation['source_epoch'])
            boot_id = cold.get('boot_id')
            try:
                if str(uuid.UUID(boot_id)) != boot_id or boot_id == old_b_boot:
                    raise RuntimeError('rejoin boot identity did not change')
            except (TypeError, ValueError, AttributeError) as exc:
                raise RuntimeError('rejoin boot identity is malformed') from exc
            cold_config = cold.get('config', {})
            services = cold.get('services', {})
            if (cold.get('operation') != operation_id or cold.get('epoch') != operation['source_epoch']
                    or cold.get('authority') not in ('absent', 'stale') or cold.get('cgroup') != 'empty'
                    or cold.get('mutators') != 'none' or cold_config.get('role') != 'writer'
                    or cold_config.get('epoch') != operation['source_epoch']
                    or cold_config.get('binaries') != expected_config.get('binaries')
                    or cold_config.get('support') != expected_config.get('support')
                    or set(services) != {'node_service', 'restart', 'legacy_services'}
                    or services.get('node_service') not in ('static', 'disabled')
                    or services.get('restart') != 'no' or services.get('legacy_services') != 'masked'
                    or not isinstance(cold.get('replica_config'), str)
                    or not re.fullmatch('[0-9a-f]{64}', cold.get('config_sha', ''))
                    or not re.fullmatch('[0-9a-f]{64}', cold.get('replica_sha', ''))):
                raise RuntimeError('B did not boot into the retained cold quarantine')
            state['B'] = {'boot_id': boot_id, 'config_sha': cold['config_sha'],
                          'replica_sha': cold['replica_sha']}
            return {'receipt': receipt, 'readiness': readiness, 'cold': cold, 'boot_id': boot_id}

        def rejoin_node():
            result = io.remote('B', 'rejoin', {'new_epoch': operation['new_epoch']}, epoch=operation['source_epoch'])
            transition.validate_cut(result.get('cut'))
            if (result.get('operation') != operation_id or result.get('role') != 'standby'
                    or result.get('epoch') != operation['new_epoch']
                    or result.get('original_epoch') != operation['source_epoch']
                    or result.get('original_boot_id') != state['B']['boot_id']
                    or result.get('original_config_sha') != state['B']['config_sha']
                    or result.get('original_replica_sha') != state['B']['replica_sha']):
                raise RuntimeError('B rejoin result is not bound to the retained original')
            return result

        def verify():
            deadline = time.monotonic() + 90
            while True:
                result = None
                try:
                    result = io.remote('B', 'probe', epoch=operation['new_epoch'],
                                       timeout=max(1, min(10, deadline-time.monotonic())))
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass  # The native probe refuses while startup health is false.
                if result is not None:
                    config_value, value = result.get('config', {}), result.get('status', {})
                    positions, processes = value.get('positions'), value.get('processes')
                    transition.validate_cut(positions)
                    if (result.get('boot_id') != state['B']['boot_id']
                            or config_value.get('role') != 'standby'
                            or config_value.get('epoch') != operation['new_epoch']
                            or config_value.get('binaries') != expected_config.get('binaries')
                            or config_value.get('support') != expected_config.get('support')
                            or value.get('role') != 'standby' or value.get('epoch') != operation['new_epoch']
                            or value.get('healthy') is not True or value.get('trailbase_running') is not False
                            or not isinstance(processes, dict) or set(processes) != set(node.DBS)
                            or any(alive is not True for alive in processes.values())
                            or value.get('refusals') != []):
                        raise RuntimeError('B native standby identity or process health differs')
                    if all(positions[db] >= state['A']['positions'][db] for db in node.DBS):
                        break
                if time.monotonic() >= deadline:
                    raise RuntimeError('B did not reach the captured A same-epoch cut')
                time.sleep(1)
            final_a = io.remote('A', 'probe', epoch=operation['new_epoch'])
            writer_probe(final_a, state['A']['boot_id'])
            if hashlib.sha256(ingress.read_bytes()).hexdigest() != route.get('config_sha'):
                raise RuntimeError('verified A ingress route changed during rejoin')
            return {'writer': 'A', 'epoch': operation['new_epoch'],
                    'writer_probe': final_a, 'followers': result}

        try:
            if not boot_done:
                journal.step('rejoin_boot', boot)
            else:
                retained = previous['rejoin_boot']['cold']
                if hashlib.sha256(ingress.read_bytes()).hexdigest() != route.get('config_sha'):
                    raise RuntimeError('verified A route changed after reconciliation')
                current_a = io.remote('A', 'probe', epoch=operation['new_epoch'])
                state['A'] = {'boot_id': expected_a_boot, 'positions': writer_probe(current_a, expected_a_boot)}
                state['B'] = {'boot_id': retained['boot_id'], 'config_sha': retained['config_sha'],
                              'replica_sha': retained['replica_sha']}
                if io.remote('B', 'inspect-cold', epoch=operation['source_epoch']) != retained:
                    raise RuntimeError('B cold state changed after reconciliation')
            journal.step('rejoin', rejoin_node)
            journal.step('verify_redundancy', verify)
            journal.finish()
            if maintenance.exists(): maintenance.unlink()
            return operation_id
        except BaseException as exc:
            path = work / 'failure.json'
            if not path.exists():
                transition.atomic_json(path, {'phase': D3_PHASES[min(journal.next, len(D3_PHASES)-1)],
                                              'error': type(exc).__name__})
            raise


def reconcile_rejoin_boot(config, operation_id, *, root=Path('/var/lib/hat-control'), ingress=Path('/etc/hat-ingress/haproxy.cfg'),
                          maintenance=Path('/etc/hat-control/maintenance'), io_factory=None):
    """Reconcile one retained D3 boot failure without issuing another power action."""
    import transition
    root, ingress, maintenance = map(Path, (root, ingress, maintenance))
    if io_factory is None: io_factory = ControlIO
    with Journal(root) as journal:
        operation, previous = journal._boundary(operation_id, 10, ('B','A'))
        _validate_d3_proof(operation, previous)
        journal.operation=operation; journal.next=10; journal.pending=True
        work = root / operation_id
        failure = work / 'failure.json'
        private_file(failure)
        if json.loads(failure.read_text()) != {'phase': 'rejoin_boot', 'error': 'RuntimeError'}:
            raise RuntimeError('not the retained rejoin boot failure')
        if any((work / name).exists() or (work / name).is_symlink() for name in ('reconciliation-rejoin-boot.json', 'failure.before-reconciliation-rejoin-boot.json')):
            raise RuntimeError('rejoin boot reconciliation already attempted')
        # ControlIO records each command as intent/stdout/outcome.  Accept only one
        # successful power-on and one matching inspect-cold response.
        def stdout_records():
            values=[]
            for path in sorted(work.glob('*.stdout')):
                private_file(path)
                if path.stat().st_size > 4*1024*1024: raise RuntimeError('oversized original command evidence')
                try: value=json.loads(path.read_text())
                except (ValueError, OSError): continue
                stem=path.with_suffix('')
                intent=stem.with_suffix('.intent.json'); outcome=stem.with_suffix('.outcome.json')
                if intent.exists(): private_file(intent)
                if outcome.exists(): private_file(outcome)
                values.append((path,value,
                    json.loads(intent.read_text()) if intent.exists() else None,
                    json.loads(outcome.read_text()) if outcome.exists() else None))
            return values
        records=stdout_records()
        powers=[]; colds=[]
        target=config.get('fence_targets',{}).get('B')
        if not isinstance(target,dict) or set(target)!=ControlIO._TARGET_FIELDS or target.get('node')!='fm2' or target.get('address')!=config['nodes']['B']['address']:
            raise RuntimeError('B trusted pin differs')
        power_argv=['/root/.config/hat/m1-fence-linode','power-on','/etc/hat-control/target-fm2.json']
        cold_argv=['ssh',*ControlIO.SSH_FLAGS,'root@'+config['nodes']['B']['address'],'hat-node']
        for path,value,intent,outcome in records:
            if not isinstance(value,dict): continue
            argv=intent.get('argv') if isinstance(intent,dict) else None
            proven=(isinstance(outcome,dict) and outcome.get('argv')==argv
                    and type(outcome.get('returncode')) is int and outcome['returncode']==0
                    and outcome.get('uncertain') is False)
            if value.get('action')=='power-on':
                if not proven or argv!=power_argv or value.get('target')!=target or value.get('state')!='running':
                    raise RuntimeError('original power command provenance differs')
                powers.append((path,value))
            if (value.get('operation')==operation_id and value.get('epoch')==operation['source_epoch']
                    and value.get('config',{}).get('role')=='writer' and 'authority' in value):
                if not proven or argv!=cold_argv: raise RuntimeError('original cold command provenance differs')
                colds.append((path,value))
        if len(powers)!=1 or len(colds)!=1:
            raise RuntimeError('original boot evidence is missing or ambiguous')
        original_receipt, original_cold = powers[0][1], colds[0][1]
        services=original_cold.get('services',{})
        source_config=previous['preflight'].get('source_health',{}).get('probe',{}).get('config')
        if (original_cold.get('authority')!='absent' or original_cold.get('cgroup')!='empty'
                or original_cold.get('mutators')!='none' or original_cold.get('config')!=source_config
                or set(services)!={'node_service','restart','legacy_services'}
                or services.get('node_service') not in ('static','disabled') or services.get('restart')!='no'
                or services.get('legacy_services')!='masked'
                or any(not re.fullmatch('[0-9a-f]{64}',original_cold.get(k,'')) for k in ('config_sha','replica_sha'))):
            raise RuntimeError('original cold quarantine differs')
        # Historical receipt structure/order only; current provider identity is freshly inspected below.
        try:
            def historical_stamp(text):
                value=datetime.datetime.fromisoformat(text.replace('Z','+00:00'))
                if value.tzinfo is None: raise ValueError('missing receipt timezone')
                return value.timestamp()
            requested=historical_stamp(original_receipt['request']['time'])
            completed=historical_stamp(original_receipt['completion']['time'])
            observations=original_receipt['observations'];identity=observations[-1]['identity']
            stamps=[historical_stamp(o['time']) for o in observations]
            addresses={r[4][0] for r in socket.getaddrinfo(target['address'],None,socket.AF_INET,socket.SOCK_STREAM)}
            if (not isinstance(original_receipt['request']['id'],str) or not original_receipt['request']['id']
                    or len(stamps)<2 or not requested<=completed<=stamps[-1]<=time.time()+5
                    or any(t<requested for t in stamps) or stamps!=sorted(stamps)
                    or observations[-1]['state']!='running' or type(identity.get('instance_id')) is not int
                    or identity['instance_id']!=target['instance_id'] or not addresses
                    or not addresses<=set(identity['addresses'])
                    or identity.get('provider_label')!=target['provider_label']):
                raise ValueError('invalid historical receipt')
        except (KeyError,TypeError,ValueError,IndexError,AttributeError) as exc:
            raise RuntimeError('historical power receipt is malformed') from exc
        old_source=previous.get('preflight',{}).get('source_boot')
        try:
            if str(uuid.UUID(original_cold.get('boot_id')))!=original_cold['boot_id'] or original_cold['boot_id']==old_source:
                raise ValueError('boot not new')
        except (ValueError,TypeError,AttributeError) as exc:
            raise RuntimeError('original cold boot identity is not new') from exc
        # Commit the one-shot marker before any provider or node read.
        marker=work/'reconciliation-rejoin-boot.json'
        from transition import atomic_json
        atomic_json(marker, {'operation': operation_id, 'action': 'reconcile-rejoin-boot',
                             'failure_sha': hashlib.sha256(failure.read_bytes()).hexdigest(),
                             'receipt_sha': hashlib.sha256(json.dumps(original_receipt,sort_keys=True).encode()).hexdigest(),
                             'cold_sha': hashlib.sha256(json.dumps(original_cold,sort_keys=True).encode()).hexdigest()})
        route=previous['route']; state={'A':{},'ingress_touched':False}
        io=io_factory(journal,config,operation,work,state,maintenance,ingress)
        expected_config=previous.get('activate',{}).get('probe',{}).get('config',{})
        expected_boot=previous.get('activate',{}).get('probe',{}).get('boot_id') or previous['preflight'].get('candidate_boot')
        if route.get('writer')!='A' or route.get('epoch')!=operation['new_epoch'] or hashlib.sha256(ingress.read_bytes()).hexdigest()!=route.get('config_sha'):
            raise RuntimeError('verified A route is not current')
        fresh_a=io.remote('A','probe',epoch=operation['new_epoch'])
        status=fresh_a.get('status',{}); cfg=fresh_a.get('config',{})
        transition.validate_cut(status.get('positions'))
        if (fresh_a.get('boot_id')!=expected_boot or cfg.get('role')!='writer' or cfg.get('epoch')!=operation['new_epoch']
                or cfg.get('binaries')!=expected_config.get('binaries') or cfg.get('support')!=expected_config.get('support')
                or status.get('epoch')!=operation['new_epoch'] or status.get('healthy') is not True or status.get('trailbase_running') is not True):
            raise RuntimeError('A is not the retained healthy writer')
        fresh_provider=io.fence('inspect','running',label='B')
        state['B']={'boot_id':original_cold['boot_id']}
        fresh_cold=io.remote('B','inspect-cold',epoch=operation['source_epoch'])
        if fresh_cold != original_cold or fresh_cold.get('authority')!='absent' or fresh_cold.get('boot_id')==old_source:
            raise RuntimeError('current B cold evidence differs from retained boot evidence')
        evidence={'receipt':original_receipt,'fresh_provider':fresh_provider,'cold':fresh_cold,'reconciliation':json.loads(marker.read_text()),'a_probe':fresh_a}
        checked,_=journal._boundary(operation_id,10,('B','A'))
        if checked!=operation: raise RuntimeError('operation changed during reconciliation')
        with journal.db:
            journal.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(operation_id,10,'rejoin_boot','done',json.dumps(evidence,allow_nan=False)))
        journal.operation=operation; journal.next=11; journal.pending=False
        archived=work/'failure.before-reconciliation-rejoin-boot.json'
        failure.rename(archived)
        fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        journal.operation=None  # Re-read the reconciled boundary while retaining this same authority lock.
        return rejoin(config, operation_id, root=root, ingress=ingress, maintenance=maintenance,
                      io_factory=io_factory, boot_done=True, _journal=journal)


def main():
    parser=argparse.ArgumentParser(description='Manual D2/D3 controller; no automatic recovery or force flag')
    parser.add_argument('command',choices=['switchover','recover','rejoin','reconcile-rejoin-boot','ingress-check','reconcile-compare','reconcile-verify']); parser.add_argument('target',nargs='?'); parser.add_argument('operation',nargs='?')
    args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('root controller required')
    os.umask(0o077)
    if args.command == 'ingress-check' and (args.target is not None or args.operation is not None):
        parser.error('extra arguments are not accepted')
    if args.command=='ingress-check':
        import node
        raise SystemExit(0 if ingress_allowed(Path('/var/lib/hat-control'),Path('/etc/hat-control/maintenance'),
                         Path('/run/hat-control-route.json'),Path('/etc/hat-ingress/haproxy.cfg'),node.boot_id()) else 1)
    if args.command in ('switchover','recover') and args.operation is not None:
        parser.error('extra arguments are not accepted')
    if args.command=='switchover' and args.target!='B': parser.error('switchover requires target B')
    if args.command=='recover' and args.target!='A': parser.error('recover requires target A')
    if args.command=='rejoin' and (args.target!='B' or not re.fullmatch('[0-9a-f]{32}',args.operation or '')):
        parser.error('rejoin requires B and an exact operation ID')
    if args.command=='reconcile-rejoin-boot' and (args.operation is not None or not re.fullmatch('[0-9a-f]{32}',args.target or '')):
        parser.error('reconcile-rejoin-boot requires one exact operation ID')
    if args.command in ('reconcile-compare','reconcile-verify') and (args.operation is not None or not re.fullmatch('[0-9a-f]{32}',args.target or '')):parser.error('reconciliation requires exact operation ID')
    path=Path('/etc/hat-control/config.json'); private_file(path)
    config=json.loads(path.read_text())
    if config['hostname'] != socket.gethostname(): raise ValueError('wrong designated controller')
    if args.command == 'recover':
        from recovery import recover
        print(recover(config, control_module=sys.modules[__name__]))
    elif args.command == 'rejoin':
        print(rejoin(config, args.operation))
    elif args.command == 'reconcile-rejoin-boot':
        print(reconcile_rejoin_boot(config, args.target))
    else:
        switchover(config,reconcile=args.target if args.command in ('reconcile-compare','reconcile-verify') else None,
                   verification_only=args.command=='reconcile-verify')

if __name__ == '__main__': main()
