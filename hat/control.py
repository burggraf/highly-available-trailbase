#!/usr/bin/env python3
"""D2 manual switchover controller; no automatic recovery or force bypass."""
import argparse
from contextlib import closing
import datetime
import descriptor
import client
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
RESTORE_CONTRACT = 'hat-restore-acceptance-1'
LEGACY_RESTORE_CONTRACT = 'legacy'
_OPERATIONS_LEGACY_SQL = '''CREATE TABLE operations (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
    source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)))'''
_OPERATIONS_SQL = _OPERATIONS_LEGACY_SQL[:-1] + ",\n    restore_contract TEXT NOT NULL DEFAULT 'legacy' CHECK(restore_contract IN ('legacy','hat-restore-acceptance-1')))"
_STEPS_SQL = '''CREATE TABLE steps (
    operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
    phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
    evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status))'''
_UNFINISHED_SQL = 'CREATE UNIQUE INDEX one_unfinished ON operations(complete) WHERE complete=0'


def _canonical_ddl(value):
    """Canonicalize SQL while distinguishing identifiers from string literals."""
    if not isinstance(value, str): return value
    out=[]; i=0
    while i < len(value):
        if value[i].isspace(): i += 1; continue
        if value.startswith('--', i):
            i=value.find('\\n', i+2); i=len(value) if i < 0 else i+1; continue
        if value.startswith('/*', i):
            end=value.find('*/', i+2)
            if end < 0: raise ValueError('malformed journal DDL')
            i=end+2; continue
        ch=value[i]
        if ch=="'":
            end=i+1
            while end<len(value):
                if value[end]=="'":
                    if end+1<len(value) and value[end+1]=="'": end+=2; continue
                    end+=1; break
                end+=1
            if end > len(value) or end == 0 or value[end-1] != "'": raise ValueError('malformed journal DDL')
            out.append(value[i:end]); i=end; continue
        if ch in '\"`[':
            close=']' if ch=='[' else ch; end=value.find(close,i+1)
            if end<0: raise ValueError('malformed journal DDL')
            out.append(value[i+1:end].lower()); i=end+1; continue
        if ch.isalnum() or ch=='_':
            end=i+1
            while end<len(value) and (value[end].isalnum() or value[end] in '_$'): end+=1
            out.append(value[i:end].lower()); i=end; continue
        out.append(ch); i+=1
    return ''.join(out)


def _normalized_sql(value):
    return _canonical_ddl(value)


_LEGACY_OP_COLUMNS=(('id','TEXT',0,None,1,0),('source','TEXT',1,None,0,0),('target','TEXT',1,None,0,0),('source_epoch','TEXT',1,None,0,0),('new_epoch','TEXT',1,None,0,0),('complete','INTEGER',1,'0',0,0))
_NEW_OP_COLUMNS=_LEGACY_OP_COLUMNS+(('restore_contract','TEXT',1,"'legacy'",0,0),)
_STEP_COLUMNS=(('operation','TEXT',1,None,1,0),('position','INTEGER',1,None,2,0),('phase','TEXT',1,None,0,0),('status','TEXT',1,None,3,0),('evidence','TEXT',1,None,0,0))

def _schema_objects(db):
    return {(kind,name) for kind,name in db.execute("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")}

def _check_table(db,name,expected):
    actual=[]
    for row in db.execute('PRAGMA table_xinfo('+name+')'):
        if len(row)!=7 or row[6] not in (0,): raise ValueError('unrecognized journal table')
        actual.append(tuple(row[1:]))
    if tuple(actual)!=expected: raise ValueError('unrecognized journal table')

def _check_indexes(db):
    indexes=db.execute('PRAGMA index_list(operations)').fetchall()
    if len(indexes)!=3 or not any(r[1]=='one_unfinished' and r[2]==1 and r[3]=='c' and r[4]==1 for r in indexes):
        raise ValueError('unrecognized journal indexes')
    if db.execute('PRAGMA index_list(steps)').fetchall() and len(db.execute('PRAGMA index_list(steps)').fetchall())!=1: raise ValueError('unrecognized journal indexes')
    one=db.execute('PRAGMA index_info(one_unfinished)').fetchall()
    if [(r[1],r[2]) for r in one]!=[(5,'complete')]: raise ValueError('unrecognized journal index')
    for table, expected in (('operations',{'id','new_epoch'}),('steps',{'operation'})):
        for row in db.execute('PRAGMA index_list('+table+')'):
            info=db.execute('PRAGMA index_info('+repr(row[1])+')').fetchall()
            cols=[r[2] for r in info]
            if row[4] and row[1].startswith('sqlite_autoindex_') and not cols: raise ValueError('unrecognized journal index')
        if table=='operations' and not any(db.execute('PRAGMA index_info('+repr(r[1])+')').fetchone() and db.execute('PRAGMA index_info('+repr(r[1])+')').fetchone()[2] in expected for r in db.execute('PRAGMA index_list(operations)')): raise ValueError('unrecognized journal index')

def _check_constraints(db, contract):
    if db.execute('PRAGMA foreign_key_list(steps)').fetchall()!=[(0,0,'operations','operation','id','NO ACTION','NO ACTION','NONE')]: raise ValueError('unrecognized journal foreign key')
    probe=sqlite3.connect(':memory:'); probe.execute('PRAGMA foreign_keys=ON')
    try:
        schemas=db.execute("SELECT sql FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END,name").fetchall()
        probe.executescript(';'.join(row[0] for row in schemas))
        try:
            probe.execute("INSERT INTO operations(id,source,target,source_epoch,new_epoch,complete) VALUES(?,?,?,?,?,?)",('a'*32,'A','B','d1-test','d1-new',1))
            probe.execute("INSERT INTO steps(operation,position,phase,status,evidence) VALUES(?,?,?,?,?)",('a'*32,0,'preflight','intent','{}'))
        except sqlite3.IntegrityError as exc:
            raise ValueError('journal constraints differ') from exc
        bad=[("INSERT INTO operations(id,source,target,source_epoch,new_epoch,complete) VALUES(?,?,?,?,?,?)",('b'*32,'A','B','d1-test','d1-new',1)),
             ("INSERT INTO operations(id,source,target,source_epoch,new_epoch,complete) VALUES(?,?,?,?,?,?)",('c'*32,'A','B','d1-test','d1-c',2)),
             ("INSERT INTO steps(operation,position,phase,status,evidence) VALUES(?,?,?,?,?)",('a'*32,0,'preflight','bad','{}')),
             ("INSERT INTO steps(operation,position,phase,status,evidence) VALUES(?,?,?,?,?)",('z'*32,1,'x','intent','{}'))]
        for sql,args in bad:
            try: probe.execute(sql,args)
            except sqlite3.IntegrityError: continue
            raise ValueError('journal constraints differ')
    finally: probe.close()

def _validate_legacy_rows(db):
    """Validate populated raw legacy rows before ALTER; this is the sole legacy reader."""
    rows=db.execute('SELECT id,source,target,complete,new_epoch FROM operations').fetchall()
    ids={row[0] for row in rows}
    if len(ids) != len(rows): raise ValueError('unrecognized legacy operation')
    for ident,source,target,complete,new_epoch in rows:
        if (not isinstance(ident,str) or not re.fullmatch(r'[0-9a-f]{32}',ident)
                or (source,target) not in (('A','B'),('B','A'))
                or not isinstance(source_epoch := db.execute('SELECT source_epoch FROM operations WHERE id=?',(ident,)).fetchone()[0],str)
                or not re.fullmatch(r'd1-[a-z0-9-]{1,125}',source_epoch)
                or not isinstance(new_epoch,str) or not re.fullmatch(r'd1-[a-z0-9-]{1,125}',new_epoch)
                or new_epoch != 'd1-'+ident or new_epoch == source_epoch
                or type(complete) is not int or complete not in (0,1)):
            raise ValueError('unrecognized legacy operation')
        plan=phase_plan(source,target)
        steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(plan) for s in ('intent','done')]
        if not steps or [step[:3] for step in steps] != expected[:len(steps)]:
            raise ValueError('unrecognized legacy operation steps')
        for _,phase,status,value in steps:
            if status=='intent' and value!='{}': raise ValueError('unrecognized legacy operation steps')
            if status=='done':
                try:
                    parsed=json.loads(value, object_pairs_hook=lambda pairs: (_ for _ in ()).throw(ValueError()) if len({k for k,v in pairs}) != len(pairs) else dict(pairs))
                except (TypeError,ValueError,json.JSONDecodeError): raise ValueError('unrecognized legacy operation steps')
                if not isinstance(parsed,dict): raise ValueError('unrecognized legacy operation steps')
        if complete and [step[:3] for step in steps] != expected:
            raise ValueError('unrecognized legacy completed operation')
    outside=db.execute('SELECT operation FROM steps WHERE operation NOT IN (SELECT id FROM operations)').fetchall()
    if outside: raise ValueError('unrecognized legacy operation reference')


def _journal_schema(db):
    """Return exact semantic journal generation; unknown or corrupt state refuses."""
    expected_sql = {
        'operations': _OPERATIONS_LEGACY_SQL,
        'steps': _STEPS_SQL,
        'one_unfinished': _UNFINISHED_SQL,
    }
    actual_sql = {name: sql for name, sql in db.execute(
        "SELECT name,sql FROM sqlite_schema WHERE name IN ('operations','steps','one_unfinished')")}
    if any(name not in actual_sql or _canonical_ddl(actual_sql[name]) != _canonical_ddl(expected_sql[name])
           for name in expected_sql):
        # The new column is the sole intentional generation difference.
        new_expected = dict(expected_sql, operations=_OPERATIONS_SQL)
        if any(name not in actual_sql or _canonical_ddl(actual_sql[name]) != _canonical_ddl(new_expected[name])
               for name in expected_sql):
            raise ValueError('unrecognized or damaged journal; reconciliation required')
    if db.execute('PRAGMA integrity_check').fetchone()!=('ok',) or db.execute('PRAGMA foreign_key_check').fetchall():
        raise ValueError('unrecognized or damaged journal; reconciliation required')
    if _schema_objects(db)!={('table','operations'),('table','steps'),('index','one_unfinished')}:
        raise ValueError('unrecognized or damaged journal; reconciliation required')
    _check_table(db,'steps',_STEP_COLUMNS); _check_indexes(db)
    columns=tuple(tuple(row[1:]) for row in db.execute('PRAGMA table_xinfo(operations)'))
    if columns==_LEGACY_OP_COLUMNS:
        contract=LEGACY_RESTORE_CONTRACT
    elif columns==_NEW_OP_COLUMNS:
        contract=RESTORE_CONTRACT
    else: raise ValueError('unrecognized or damaged journal; reconciliation required')
    _check_constraints(db,contract)
    if contract==LEGACY_RESTORE_CONTRACT:return contract
    contracts={row[0] for row in db.execute('SELECT restore_contract FROM operations')}
    if not contracts<={LEGACY_RESTORE_CONTRACT,RESTORE_CONTRACT}: raise ValueError('unknown restore contract')
    return RESTORE_CONTRACT


def phase_plan(source, target):
    try: return {('A','B'):PHASES, ('B','A'):D3_PHASES}[(source,target)]
    except KeyError as exc: raise ValueError('invalid demo transition') from exc


def private_file(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077 or s.st_nlink != 1:
        raise ValueError('controller file must be private, owned, regular and singly linked')
    return s.st_dev, s.st_ino


def _stable_private_bytes(path, strict=True):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
                or (strict and before.st_mode&0o077) or before.st_nlink!=1): raise ValueError('controller file is unsafe')
        raw=os.read(fd,before.st_size+1)
        after=os.fstat(fd)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_mode,s.st_uid,s.st_nlink)
        if len(raw)!=before.st_size or identity(before)!=identity(after): raise ValueError('controller file changed')
        return raw,identity(after)
    finally: os.close(fd)


class Journal:
    """One locked controller, committed intent before effects, no implicit recovery."""
    def __init__(self, root):
        self.root = Path(root)
        self.lock = None
        self.db = None
        self.operation = None
        self.next = 0
        self.pending = False

    # Private seams let crash tests place failure immediately around SQLite's
    # durable commit without exposing fault controls to callers.
    def _before_commit(self, label):
        return None

    def _after_commit(self, label):
        return None

    def _commit(self, label):
        self._before_commit(label)
        self.db.commit()
        self._after_commit(label)

    def _migration_alter(self):
        self.db.execute("ALTER TABLE operations ADD COLUMN restore_contract TEXT NOT NULL DEFAULT 'legacy' CHECK(restore_contract IN ('legacy','hat-restore-acceptance-1'))")

    def _before_root_fsync(self, label):
        return None

    def _after_root_fsync(self, label):
        return None

    def _root_fsync(self, label='root-fsync'):
        self._before_root_fsync(label)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self._after_root_fsync(label)

    def _before_reopen(self, path):
        return None

    def _after_reopen(self, path):
        return None

    def _reopen(self, path):
        self._before_reopen(path)
        self.db.close()
        self.db = sqlite3.connect(path, timeout=0)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=EXTRA')
        self.db.execute('PRAGMA foreign_keys=ON')
        self._after_reopen(path)

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
                if candidate.exists() or candidate.is_symlink():
                    private_file(candidate)
                    if suffix in ('-wal','-shm'): raise ValueError('WAL journal state is not accepted')
            existing = path.exists()
            if existing:
                if not path.stat().st_size: raise ValueError('empty existing journal; reconciliation required')
            else:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
            self.db = sqlite3.connect(path, timeout=0)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=EXTRA')
            self.db.execute('PRAGMA foreign_keys=ON')
            changed=not existing
            if existing:
                kind=_journal_schema(self.db)
                if kind==LEGACY_RESTORE_CONTRACT:
                    _validate_legacy_rows(self.db)
                    self.db.execute('BEGIN IMMEDIATE')
                    try:
                        self._migration_alter()
                        if _journal_schema(self.db)!=RESTORE_CONTRACT: raise ValueError('journal migration differs')
                        self._commit('migration');changed=True
                    except BaseException:
                        self.db.rollback();raise
            else:
                self.db.executescript(_OPERATIONS_SQL+';\n'+_UNFINISHED_SQL+';\n'+_STEPS_SQL+';')
            if _journal_schema(self.db)!=RESTORE_CONTRACT: raise ValueError('journal schema differs')
            if changed:
                self._root_fsync('journal-root-fsync')
                self._reopen(path)
                if _journal_schema(self.db)!=RESTORE_CONTRACT: raise ValueError('journal reopen differs')
            self.database_identity = private_file(path)
            self._root_fsync('root-fsync')
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
        if self.operation or self.db.execute("SELECT id,restore_contract FROM operations WHERE complete=0 AND restore_contract=?",(RESTORE_CONTRACT,)).fetchone() or self.db.execute("SELECT id,restore_contract FROM operations WHERE complete=0 AND restore_contract!=?",(RESTORE_CONTRACT,)).fetchone():
            raise RuntimeError('unfinished operation requires reconciliation; no retry or force')
        ident = uuid.uuid4().hex
        operation = dict(id=ident, source=source, target=target, source_epoch=source_epoch, new_epoch='d1-'+ident)
        try:
            self.db.execute('INSERT INTO operations(id,source,target,source_epoch,new_epoch,restore_contract) VALUES(?,?,?,?,?,?)',
                            (*operation.values(),RESTORE_CONTRACT))
            self._commit('begin')
        except BaseException:
            self.db.rollback(); raise
        self.operation = operation; self.next = 0; self.pending = False
        return dict(operation)

    def step(self, phase, action):
        self.check_authority()
        row=(self.db.execute('SELECT source,target,complete,restore_contract FROM operations WHERE id=?',(self.operation['id'],)).fetchone()
             if self.operation else None)
        plan=phase_plan(*row[:2]) if row and not row[2] else ()
        if (not self.operation or not row or row[:2]!=(self.operation['source'],self.operation['target'])
                or row[3]!=RESTORE_CONTRACT or self.pending or self.next >= len(plan) or plan[self.next] != phase):
            raise RuntimeError('out-of-order or uncertain step; no retry')
        self.pending = True
        try:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)', (self.operation['id'], self.next, phase, 'intent', '{}'))
            self._commit('step-intent:'+phase)
        except BaseException:
            self.db.rollback(); raise
        result = action()
        self.check_authority()
        evidence = json.dumps(result, allow_nan=False)
        try:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)', (self.operation['id'], self.next, phase, 'done', evidence))
            self._commit('step-done:'+phase)
        except BaseException:
            self.db.rollback(); raise
        self.next += 1; self.pending = False
        return result

    def _boundary(self, ident, position, direction=('A','B')):
        self.check_authority()
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{32}',ident): raise ValueError('invalid operation')
        row=self.db.execute('SELECT id,source,target,source_epoch,new_epoch,restore_contract FROM operations WHERE id=? AND complete=0',(ident,)).fetchone()
        if not row or row[1:3] != direction or row[5]!=RESTORE_CONTRACT: raise RuntimeError('operation direction, identity, or restore contract differs')
        plan=phase_plan(*row[1:3])
        if not 0 <= position < len(plan): raise RuntimeError('invalid operation boundary')
        steps=self.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(plan[:position]) for s in ('intent','done')]+[(position,plan[position],'intent')]
        if [s[:3] for s in steps]!=expected:
            raise RuntimeError('not the exact pending '+plan[position]+' boundary')
        try: evidence={p:json.loads(e) for _,p,s,e in steps if s=='done'}
        except (TypeError,ValueError) as exc: raise RuntimeError('malformed operation evidence') from exc
        return dict(zip(('id','source','target','source_epoch','new_epoch'),row[:5])),evidence

    def comparison_boundary(self, ident):
        return self._boundary(ident,5)

    def verification_boundary(self, ident):
        return self._boundary(ident,9)

    def continue_rejoin(self, ident, boot_done=False):
        self.check_authority()
        if self.operation: raise RuntimeError('journal already has an active operation')
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{32}',ident): raise ValueError('invalid operation')
        row=self.db.execute('SELECT id,source,target,source_epoch,new_epoch,restore_contract FROM operations WHERE id=? AND complete=0',(ident,)).fetchone()
        steps=self.db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
        expected=[(i,p,s) for i,p in enumerate(D3_PHASES[:10]) for s in ('intent','done')]
        if boot_done: expected += [(10,'rejoin_boot',s) for s in ('intent','done')]
        if (not row or row[1:3]!=('B','A') or row[5]!=RESTORE_CONTRACT or [s[:3] for s in steps]!=expected
                or any(e!='{}' for _,_,status,e in steps if status=='intent')
                or (self.root/ident/'failure.json').exists() or (self.root/ident/'failure.json').is_symlink()):
            raise RuntimeError('not the exact unused D3 rejoin boundary')
        try: previous={p:json.loads(e) for _,p,s,e in steps if s=='done'}
        except (TypeError,ValueError) as exc: raise RuntimeError('malformed operation evidence') from exc
        operation=dict(zip(('id','source','target','source_epoch','new_epoch'),row[:5]))
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
        import recovery
        from transition import validate_cut
        operation,previous=self.verification_boundary(ident)
        if not isinstance(result, dict) or set(result) != {'writer','epoch','positions','baseline_recheck','new_writes'}:
            raise ValueError('verification evidence shape differs')
        validate_cut(result['positions'])
        baseline = result['baseline_recheck']
        fresh = result['new_writes']
        if (not isinstance(baseline, dict) or not isinstance(baseline.get('request'), dict)
                or not isinstance(fresh, dict) or not isinstance(fresh.get('request'), dict)):
            raise ValueError('verification evidence shape differs')
        recovery.validate_acceptance_result(baseline, baseline['request'], operation)
        recovery.validate_acceptance_result(fresh, fresh['request'], operation)
        expected = previous['baseline']
        expected_positions = expected['request']['positions']
        if (result['writer']!='B' or result['epoch']!=operation['new_epoch']
                or baseline['request'].get('phase')!='verification-baseline'
                or baseline['request'].get('source')!=operation['source']
                or baseline['request'].get('target')!=operation['target']
                or baseline['request'].get('profile')!='baseline'
                or baseline['request'].get('epoch')!=operation['new_epoch']
                or baseline['request'].get('positions')!=expected_positions
                or baseline.get('signature')!=expected['signature']
                or fresh['request'].get('phase')!='new-writes'
                or fresh['request'].get('source')!=operation['source']
                or fresh['request'].get('target')!=operation['target']
                or fresh['request'].get('profile')!='fresh-writes'
                or fresh['request'].get('epoch')!=operation['new_epoch']
                or fresh['request'].get('positions')!=result['positions']
                or any(result['positions'][db]<=pos for db,pos in expected_positions.items())):
            raise ValueError('verification evidence does not reconcile baseline and fresh writes')
        try:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,9,'verify','done',json.dumps(result,allow_nan=False)))
            self._commit('accept-verification-done')
        except BaseException:
            self.db.rollback(); raise
        self.operation=operation;self.next=10;self.pending=False

    def accept_comparison(self, ident, result):
        operation,previous=self.comparison_boundary(ident)
        frozen=previous['freeze']
        if (result.get('request',{}).get('positions')!=frozen['cut'] or result.get('signature')!=frozen['signature']
                or result.get('checks',{}).get('records')!='PASS' or result.get('checks',{}).get('authentication')!='PASS'):
            raise ValueError('reconciled comparison does not match frozen cut')
        try:
            self.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,5,'compare','done',json.dumps(result,allow_nan=False)))
            self._commit('accept-comparison-done')
        except BaseException:
            self.db.rollback(); raise
        self.operation=operation;self.next=6;self.pending=False

    def finish(self):
        self.check_authority()
        row=(self.db.execute('SELECT source,target,complete,restore_contract FROM operations WHERE id=?',(self.operation['id'],)).fetchone()
             if self.operation else None)
        plan=phase_plan(*row[:2]) if row and not row[2] else ()
        steps=(self.db.execute('SELECT position,phase,status FROM steps WHERE operation=? ORDER BY rowid',(self.operation['id'],)).fetchall()
               if self.operation else [])
        expected=[(i,phase,status) for i,phase in enumerate(plan) for status in ('intent','done')]
        if (not self.operation or not row or row[:2]!=(self.operation['source'],self.operation['target'])
                or row[3]!=RESTORE_CONTRACT or self.pending or self.next != len(plan) or steps!=expected):
            raise RuntimeError('cannot complete an unfinished transition')
        try:
            changed=self.db.execute('UPDATE operations SET complete=1 WHERE id=? AND restore_contract=?', (self.operation['id'],RESTORE_CONTRACT)).rowcount
            if changed != 1: raise RuntimeError('operation restore contract differs')
            self._commit('finish')
        except BaseException:
            self.db.rollback(); raise
        self.operation = None


def process_identity(pid):
    if type(pid) is not int or pid <= 0: return None
    try:
        fields=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        return fields[19] if fields[0] not in ('Z','X') else None
    except (OSError, IndexError): return None


def _validate_d3_proof(operation, evidence, verified=True):
    """Validate canonical D3 oracle results and the distinct node restore proof."""
    import recovery
    from transition import validate_cut
    try:
        if not isinstance(evidence,dict) or operation['source']!='B' or operation['target']!='A':
            raise ValueError('invalid D3 operation proof')
        selected=evidence['select_cut']['positions'];validate_cut(selected)
        restored=evidence['restore'];validate_cut(restored['cut'])
        if not isinstance(restored['signature'],dict) or set(restored['signature']) != set(selected):
            raise ValueError('invalid D3 node restore proof')

        def report(value, phase, profile, epoch, positions=None):
            if not isinstance(value,dict) or set(value) != {'schema','request','request_sha256','databases','signature','checks'}:
                raise ValueError('invalid D3 restore report')
            recovery.validate_acceptance_result(value, value['request'], operation)
            request=value['request']
            if ((request['phase'],request['profile'],request['epoch']) != (phase,profile,epoch)
                    or positions is not None and request['positions'] != positions):
                raise ValueError('D3 restore report binding differs')
            return value

        compared=report(evidence['compare'],'compare','recovery-comparison',operation['source_epoch'],selected)
        baseline=report(evidence['baseline'],'baseline','baseline',operation['new_epoch'])
        if restored['cut']!=selected or restored['signature']!=compared['signature']:
            raise ValueError('D3 selected cut, restore, or comparison differs')
        if not verified: return
        route=evidence['route'];verification=evidence['verify']
        if (not isinstance(route,dict) or route.get('writer')!='A' or route.get('epoch')!=operation['new_epoch']
                or not re.fullmatch('[0-9a-f]{64}',route.get('config_sha',''))
                or not isinstance(verification,dict) or verification.get('writer')!='A'
                or verification.get('epoch')!=operation['new_epoch']):
            raise ValueError('D3 route or fresh-epoch verification differs')
        positions=verification['positions'];validate_cut(positions)
        new_writes=report(verification['new_writes'],'new-writes','fresh-writes',operation['new_epoch'],positions)
        baseline_positions=baseline['request']['positions']
        if any(positions[db]<=baseline_positions[db] for db in positions):
            raise ValueError('D3 new-write restore proof is not beyond baseline')
    except (KeyError,TypeError,AttributeError,ValueError) as exc:
        raise RuntimeError('D3 recovery proof differs or is malformed') from exc


def _d3_serving_state(db, ident, digest, failure, failure_snapshot=None, failure_bytes=None):
    row=db.execute('SELECT source,target,source_epoch,new_epoch,complete,restore_contract FROM operations WHERE id=?',(ident,)).fetchone()
    if not row or row[:2]!=('B','A') or row[4] or row[5]!=RESTORE_CONTRACT: return False
    steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
    base=[(i,p,s) for i,p in enumerate(D3_PHASES[:10]) for s in ('intent','done')]
    tail=[(i,p,s) for i,p in enumerate(D3_PHASES[10:],10) for s in ('intent','done')]
    if len(steps)<len(base) or len(steps)>len(base)+len(tail) or [s[:3] for s in steps] != base+tail[:len(steps)-len(base)]:
        return False
    if any(e!='{}' for _,_,status,e in steps if status=='intent'): return False
    try:
        evidence={phase:json.loads(value) for _,phase,status,value in steps if status=='done'}
        _validate_d3_proof({'id':ident,'source':row[0],'target':row[1],
                            'source_epoch':row[2],'new_epoch':row[3]},evidence)
    except (TypeError,ValueError,RuntimeError): return False
    route=evidence['route']
    if set(route)!={'writer','epoch','config_sha'} or route['config_sha']!=digest: return False
    if failure_snapshot is None:
        try: raw, identity = _stable_private_bytes(failure, strict=False)
        except FileNotFoundError: failure_snapshot = None
        except (OSError, ValueError): return False
        else:
            failure_snapshot = (identity, hashlib.sha256(raw).digest())
            failure_bytes = raw
    if failure_snapshot is not None:
        if (len(steps)-len(base))%2 != 1: return False
        try: value=json.loads(failure_bytes)
        except (ValueError,TypeError): return False
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
    if journal.db.execute('SELECT id,restore_contract FROM operations WHERE complete=0').fetchone():
        raise RuntimeError('unfinished operation has no current writer authority')
    row=journal.db.execute('SELECT id,source,target,new_epoch,restore_contract FROM operations WHERE complete=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    if not row or row[4] not in (LEGACY_RESTORE_CONTRACT,RESTORE_CONTRACT): raise RuntimeError('no completed writer authority')
    ident,source,target,epoch,_=row;plan=phase_plan(source,target)
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


def _ingress_allowed_body(root, maintenance, permit, ingress, boot, tracked=None, paths=None):
    """Boot/restart gate for exact completed, live D2 route, or verified D3 route."""
    if tracked is None: tracked = {}
    if paths is None: paths = []
    try:
        marker_present=maintenance.exists() or maintenance.is_symlink()
        permit_present=permit.exists() or permit.is_symlink()
        if marker_present: private_file(maintenance)
        path=root/'journal.db'
        if not path.exists():
            root_before=root.lstat(); ingress_before=_stable_private_bytes(ingress,strict=False)[1]
            root_after=root.lstat(); ingress_after=_stable_private_bytes(ingress,strict=False)[1]
            stable=(root_before.st_dev,root_before.st_ino,root_before.st_mtime_ns)==(root_after.st_dev,root_after.st_ino,root_after.st_mtime_ns)
            return stable and ingress_before==ingress_after and not marker_present and not permit_present
        journal_raw,journal_identity=_stable_private_bytes(path)
        ingress_raw,ingress_identity=_stable_private_bytes(ingress,strict=False)
        ingress_digest=hashlib.sha256(ingress_raw).hexdigest()
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            if db.execute('PRAGMA journal_mode').fetchone() != ('delete',): return False
            kind=_journal_schema(db)
            if kind==LEGACY_RESTORE_CONTRACT:
                _validate_legacy_rows(db)
                row=db.execute('SELECT id,source,target,complete,new_epoch FROM operations ORDER BY rowid DESC LIMIT 1').fetchone()
                operation=(*row,LEGACY_RESTORE_CONTRACT) if row else None
            else:
                operation=db.execute('SELECT id,source,target,complete,new_epoch,restore_contract FROM operations ORDER BY rowid DESC LIMIT 1').fetchone()
            if not operation:
                return (journal_identity==_stable_private_bytes(path)[1]
                        and ingress_identity==_stable_private_bytes(ingress,strict=False)[1]
                        and not marker_present and not permit_present)
            ident,source,target,complete,epoch,contract=operation
            digest=ingress_digest
            if complete:
                row=db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
                stable=(journal_identity==_stable_private_bytes(path)[1]
                        and ingress_identity==_stable_private_bytes(ingress,strict=False)[1])
                return (stable and not marker_present and not permit_present and row is not None
                        and _exact_route(json.loads(row[0]),target,epoch,digest))
            if contract!=RESTORE_CONTRACT: return False
            if (source,target)==('B','A'):
                if not re.fullmatch('[0-9a-f]{32}',ident) or not marker_present: return False
                if json.loads(maintenance.read_text())!={'operation':ident}: return False
                failure=root/ident/'failure.json'
                failure_key=str(failure)
                paths.append(failure)
                try: raw, identity = _stable_private_bytes(failure, strict=False)
                except FileNotFoundError: tracked[failure_key] = None
                else: tracked[failure_key] = (identity, hashlib.sha256(raw).digest()); tracked[failure_key+'#bytes'] = raw
                if _d3_serving_state(db,ident,digest,failure,tracked[failure_key],tracked.get(failure_key+'#bytes')):
                    return (journal_identity==_stable_private_bytes(path)[1]
                            and ingress_identity==_stable_private_bytes(ingress,strict=False)[1]
                            and not permit_present)
                steps=db.execute('SELECT position,phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',(ident,)).fetchall()
                route_pending=[(i,p,s) for i,p in enumerate(D3_PHASES[:8]) for s in ('intent','done')]+[(8,'route','intent')]
                verify_pending=[(i,p,s) for i,p in enumerate(D3_PHASES[:9]) for s in ('intent','done')]+[(9,'verify','intent')]
                if ([step[:3] for step in steps] not in (route_pending,verify_pending)
                        or any(value!='{}' for _,_,status,value in steps if status=='intent')
                        or tracked[failure_key] is not None):
                    return False
                evidence={phase:json.loads(value) for _,phase,status,value in steps if status=='done'}
                source_epoch=db.execute('SELECT source_epoch FROM operations WHERE id=?',(ident,)).fetchone()[0]
                _validate_d3_proof({'id':ident,'source':source,'target':target,
                                    'source_epoch':source_epoch,'new_epoch':epoch},evidence,False)
                if [step[:3] for step in steps]==verify_pending:
                    route=evidence.get('route',{})
                    if (set(route)!={'writer','epoch','config_sha'} or route.get('writer')!='A'
                            or route.get('epoch')!=epoch or route.get('config_sha')!=digest): return False
                private_file(permit);value=json.loads(permit.read_text())
                if not isinstance(value,dict) or set(value)!={'operation','boot_id','pid','birth','config_sha'}: return False
                birth=process_identity(value['pid'])
                return (journal_identity==_stable_private_bytes(path)[1]
                        and ingress_identity==_stable_private_bytes(ingress,strict=False)[1]
                        and value['operation']==ident and value['boot_id']==boot and birth is not None
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
            return (journal_identity==_stable_private_bytes(path)[1]
                    and ingress_identity==_stable_private_bytes(ingress,strict=False)[1]
                    and value['operation']==ident and value['boot_id']==boot and birth is not None
                    and value['birth']==birth and value['config_sha']==digest)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error): return False


def _ingress_file_snapshot(root, paths):
    root = Path(root)
    parent = root.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError('controller directory is unsafe')
    snapshot = {'root': (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_nlink)}
    for path in paths:
        try:
            raw, identity = _stable_private_bytes(path, strict=False)
        except FileNotFoundError:
            snapshot[str(path)] = None
        else:
            snapshot[str(path)] = (identity, hashlib.sha256(raw).digest())
    return snapshot


def _ingress_file_finalize(root, paths, snapshot, allowed):
    if _INGRESS_PRE_FINALIZE_HOOK is not None:
        _INGRESS_PRE_FINALIZE_HOOK()
    root_stat = Path(root).lstat()
    if (root_stat.st_dev, root_stat.st_ino, root_stat.st_mode, root_stat.st_uid, root_stat.st_nlink) != snapshot['root']:
        return False
    for path in paths:
        key = str(path)
        try:
            raw, identity = _stable_private_bytes(path, strict=False)
        except FileNotFoundError:
            if snapshot[key] is not None: return False
        except (OSError, ValueError):
            return False
        else:
            if snapshot[key] is None or snapshot[key] != (identity, hashlib.sha256(raw).digest()): return False
    return bool(allowed)


# Private test seam only; callers cannot supply an interleaving hook.
_INGRESS_PRE_FINALIZE_HOOK = None


def ingress_allowed(root, maintenance, permit, ingress, boot):
    root = Path(root)
    paths = [root/'journal.db', Path(ingress), Path(maintenance), Path(permit)]
    paths += [root/('journal.db'+suffix) for suffix in ('-wal', '-shm', '-journal')]
    try:
        snapshot = _ingress_file_snapshot(root, paths)
        if any(snapshot[str(path)] is not None for path in paths[-3:]): return False
        allowed = _ingress_allowed_body(root, maintenance, permit, ingress, boot, snapshot, paths)
        return _ingress_file_finalize(root, paths, snapshot, allowed)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error):
        return False


def reconcile_existing(journal, maintenance, stop_ingress, ingress):
    from transition import atomic_json
    journal.check_authority()
    row=journal.db.execute('SELECT id,restore_contract FROM operations WHERE complete=0').fetchone()
    if row:
        ident,contract=row;safe=False
        try:
            if contract==RESTORE_CONTRACT and maintenance.exists():
                private_file(maintenance)
                safe=(json.loads(maintenance.read_text())=={'operation':ident}
                      and _d3_serving_state(journal.db,ident,hashlib.sha256(ingress.read_bytes()).hexdigest(),journal.root/ident/'failure.json'))
        except (OSError,ValueError,KeyError,TypeError,sqlite3.Error): pass
        if safe: raise RuntimeError('verified D3 operation awaits explicit rejoin; safe A route preserved')
        try:
            if not maintenance.exists(): atomic_json(maintenance,{'operation':ident})
        finally: stop_ingress()
        raise RuntimeError('unfinished operation: ingress closed; explicit reconciliation required')
    completed=journal.db.execute('SELECT id,target,new_epoch,restore_contract FROM operations WHERE complete=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    if completed:
        ident,target,epoch,contract=completed
        if contract not in (LEGACY_RESTORE_CONTRACT,RESTORE_CONTRACT): raise RuntimeError('completed restore contract differs')
        route=journal.db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='route' AND status='done'",(ident,)).fetchone()
        digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
        try:
            route_value=json.loads(route[0]) if route else None
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


def _copy_bound_input(source, destination, mode, uid, gid, expected_sha, expected_identity=None, limit=4 * 1024 * 1024, private=True, fsync=None, label='copy'):
    """Copy through one descriptor authority; callers retain longer-lived handles."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    trusted = {0, os.geteuid()}
    expected_mode = stat.S_IMODE(expected_identity[2]) if expected_identity is not None else (0o600 if private else None)
    with descriptor.DescriptorAuthority.open_file(
            source, trusted_root='/', trusted_uids=trusted, expected_uid=uid,
            expected_gid=(expected_identity[4] if expected_identity is not None else None),
            expected_mode=expected_mode, expected_nlink=1,
            expected_size=(expected_identity[6] if expected_identity is not None else None),
            expected_sha256=expected_sha, limit=limit) as bound, \
         descriptor.DescriptorAuthority.open_directory(
            destination.parent, trusted_root='/', trusted_uids=trusted) as parent:
        identity = bound.identity
        if expected_identity is not None and identity != expected_identity:
            raise ValueError('source identity is not trusted')
        copied = bound.copy_to(parent, destination.name, mode=mode, uid=uid, gid=gid, fsync=fsync, label=label)
        descriptor.close_all([copied])
        bound.recheck(); parent.recheck()
        return (identity[0], identity[1], stat.S_IMODE(identity[2]), *identity[3:])


def _open_held_inputs(expected, trusted_uids=None):
    held = []
    trusted_uids = {0, os.geteuid()} if trusted_uids is None else trusted_uids
    try:
        for path, uid, gid, mode, limit in expected:
            held.append(descriptor.DescriptorAuthority.open_file(
                path, trusted_root='/', trusted_uids=trusted_uids,
                expected_uid=uid, expected_gid=gid, expected_mode=mode,
                expected_nlink=1, limit=limit))
        return held
    except BaseException:
        descriptor.close_all(held)
        raise


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

    def _before_fsync(self, label, path):
        return None

    def _after_fsync(self, label, path):
        return None

    def _before_result_read(self, path):
        return None

    def _after_result_read(self, path):
        return None

    def _before_result_recheck(self, path):
        return None

    def _after_result_recheck(self, path):
        return None

    def _read_result(self, authority, path):
        self._before_result_read(path)
        value = authority.read()
        self._after_result_read(path)
        return value

    def _recheck_result(self, authority, path):
        self._before_result_recheck(path)
        authority.recheck()
        self._after_result_recheck(path)

    def _fsync(self, fd, label, path):
        path = Path(path)
        self._before_fsync(label, path)
        os.fsync(fd)
        self._after_fsync(label, path)

    def _copy_bound(self, source, destination, mode, uid, gid, expected_sha, expected_identity=None, label='copy'):
        return _copy_bound_input(source, destination, mode, uid, gid, expected_sha,
                                 expected_identity, fsync=self._fsync, label=label)

    def _durable_json(self, path, value, label='json'):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'), allow_nan=False)
            stream.flush()
            self._fsync(stream.fileno(), label + '.file', path)
        fd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self._fsync(fd, label + '.dir', self.work)
        finally:
            os.close(fd)

    def _durable_bytes(self, path, raw, label='bytes', mode=0o600, uid=None, gid=None):
        path = Path(path)
        raw = bytes(raw)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0: raise OSError('short durable write')
                view = view[written:]
            if mode != 0o600:
                os.fchmod(fd, mode)
            if uid is not None or gid is not None:
                os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
            self._fsync(fd, label + '.file', path)
        finally: os.close(fd)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: self._fsync(directory, label + '.dir', path.parent)
        finally: os.close(directory)

    def _reopen_exact_bytes(self, path, expected, *, mode=None, uid=None, gid=None):
        """Reopen a durable artifact and verify its complete content and identity."""
        path = Path(path)
        expected = bytes(expected)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or mode is not None and stat.S_IMODE(info.st_mode) != mode
                    or uid is not None and info.st_uid != uid
                    or gid is not None and info.st_gid != gid):
                raise ValueError('durable file identity differs')
            chunks = []; count = 0
            while True:
                part = os.read(fd, 65536)
                if not part: break
                chunks.append(part); count += len(part)
            actual = b''.join(chunks)
            if count != len(expected) or hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest() or actual != expected:
                raise ValueError('durable file content differs')
            if os.fstat(fd).st_size != count:
                raise ValueError('durable file length differs')
        finally:
            os.close(fd)

    @staticmethod
    def _bounded_error_type(exc):
        value = type(exc).__name__
        return value if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', value) else 'Error'

    def _committed_preflight_authority(self, required=True):
        import recovery
        try:
            row = self.journal.db.execute(
                "SELECT evidence FROM steps WHERE operation=? AND phase='preflight' AND status='done'",
                (self.operation['id'],)).fetchone()
        except AttributeError as exc:
            if not required: return None
            raise ValueError('committed preflight authority is unavailable') from exc
        if row is None:
            if not required: return None
            raise ValueError('committed preflight authority is unavailable')
        try:
            evidence = json.loads(row[0])
            authority = evidence['ledger_authority']
            recovery._authority(authority, self.operation,
                                'recovery-comparison' if self.operation['source'] == 'B' else 'comparison')
            return authority
        except (TypeError, KeyError, ValueError, IndexError, json.JSONDecodeError) as exc:
            raise ValueError('committed preflight authority is unavailable') from exc

    def _authorized_manifests(self):
        support_names = ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')
        manifests = []
        for value in self.state.values():
            config = value.get('config') if isinstance(value, dict) else None
            if isinstance(config, dict) and ('support' in config or 'binaries' in config):
                if set(config.get('support', {})) != set(support_names) or set(config.get('binaries', {})) != {'trail', 'litestream'}:
                    raise ValueError('authorized writer release identity is unavailable')
                manifests.append((config['support'], config['binaries']))
        committed = self._committed_preflight_authority(required=False)
        if committed is not None:
            manifests.append((committed['support'], committed['binaries']))
        if not manifests or any(item != manifests[0] for item in manifests[1:]):
            raise ValueError('authorized writer release identity is unavailable')
        return support_names, *manifests[0]

    def capture_protected_authority(self, ledger, origin, support=None, binaries=None):
        import recovery
        ledger = Path(ledger).absolute()
        if support is None or binaries is None:
            _, support, binaries = self._authorized_manifests()
        with descriptor.DescriptorAuthority.open_file(
                ledger, trusted_root='/', trusted_uids={0, os.geteuid()},
                expected_uid=os.geteuid(), expected_mode=0o600, expected_nlink=1,
                limit=4 << 20) as selected:
            identity = selected.identity
            authority = {'schema': recovery._AUTHORITY_SCHEMA, 'operation': self.operation['id'],
                         'origin': origin,
                         'ledger': {'path': str(ledger), 'device': identity[0], 'inode': identity[1],
                                    'mode': stat.S_IMODE(identity[2]), 'uid': identity[3],
                                    'links': identity[5], 'bytes': identity[6], 'sha256': selected.sha256},
                         'support': support, 'binaries': binaries}
            recovery._authority(authority, self.operation,
                                'recovery-comparison' if origin == 'd3-recovery-input' else 'comparison')
            return authority

    def authorize_fresh_writes(self, ledger):
        """Bind the just-exclusive-created fresh ledger before any oracle request."""
        import recovery
        ledger = Path(ledger).absolute()
        if ledger != self.work.absolute() / 'new-writes.jsonl' or hasattr(self, '_fresh_writes'):
            raise ValueError('unexpected fresh ledger authority')
        _, support, binaries = self._authorized_manifests()
        selected = descriptor.DescriptorAuthority.open_file(
            ledger, trusted_root=self.work.absolute(), trusted_uids={0, os.geteuid()},
            expected_uid=os.geteuid(), expected_mode=0o600, expected_nlink=1, limit=4 << 20)
        try:
            identity = selected.identity
            authority = {'schema': recovery._AUTHORITY_SCHEMA, 'operation': self.operation['id'],
                         'origin': 'current-verify-exclusive',
                         'ledger': {'path': str(ledger), 'device': identity[0], 'inode': identity[1],
                                    'mode': stat.S_IMODE(identity[2]), 'uid': identity[3],
                                    'links': identity[5], 'bytes': identity[6], 'sha256': selected.sha256},
                         'support': support, 'binaries': binaries}
            self._durable_bytes(self.work / 'new-writes-input-authority.json',
                                recovery.canonical_json(authority))
            self._fresh_writes = selected, authority
            return authority
        except BaseException:
            descriptor.close_all([selected])
            raise

    def _close_fresh_writes(self):
        value = getattr(self, '_fresh_writes', None)
        if value is not None:
            del self._fresh_writes
            descriptor.close_all([value[0]])

    def _before_command_spawn(self, argv):
        """Crash-test boundary after durable command intent and before spawn."""
        return None

    def _after_command_start(self, process):
        """Crash-test boundary after Popen proves a child may exist."""
        return None

    def _before_command_timeout(self, process):
        """Crash-test boundary before strict cleanup of a timed-out child."""
        return None

    def _stop_command(self, process):
        """Do not leave an uncertain command running after communication failure."""
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)

    def _record_command_outcome(self, path, argv, *, returncode, uncertain, error=None):
        value = {'argv': argv, 'returncode': returncode, 'uncertain': uncertain}
        if error is not None:
            value['error_type'] = self._bounded_error_type(error)
        try:
            self.journal.check_authority()
            self._durable_json(path, value, label='command-outcome')
        except BaseException:
            # Never replace the command's original failure with evidence cleanup.
            pass

    def command(self, args, data=None, timeout=180):
        self.journal.check_authority()
        argv = list(args)
        prefix = self.work / str(time.time_ns())
        intent = prefix.with_suffix('.intent.json')
        self._durable_json(intent, {'argv': argv}, label='command-intent')
        self._before_command_spawn(argv)
        stdout = prefix.with_suffix('.stdout')
        stderr = prefix.with_suffix('.stderr')
        out_fd = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        err_fd = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        process = None
        try:
            with os.fdopen(out_fd, 'wb') as out, os.fdopen(err_fd, 'wb') as err:
                try:
                    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else None,
                                               stdout=out, stderr=err)
                except BaseException as exc:
                    self._record_command_outcome(prefix.with_suffix('.outcome.json'), argv,
                                                 returncode=None, uncertain=False, error=exc)
                    raise
                try:
                    self._after_command_start(process)
                    process.communicate(input=data, timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    try:
                        self._before_command_timeout(process)
                        self._stop_command(process)
                    finally: self._record_command_outcome(prefix.with_suffix('.outcome.json'), argv,
                                                          returncode=None, uncertain=True, error=exc)
                    raise
                except BaseException as exc:
                    try: self._stop_command(process)
                    finally: self._record_command_outcome(prefix.with_suffix('.outcome.json'), argv,
                                                          returncode=None, uncertain=True, error=exc)
                    raise
        finally:
            if process is not None and process.poll() is None:
                try: self._stop_command(process)
                except BaseException: pass
        self.journal.check_authority()
        self._record_command_outcome(prefix.with_suffix('.outcome.json'), argv,
                                     returncode=process.returncode, uncertain=False)
        if process.returncode:
            raise RuntimeError('command failed; protected stdout/stderr retained')
        if stdout.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('oversized command result')
        return stdout.read_bytes()

    _REMOTE_ACTIONS = {
        'probe-source': ('probe', 'source_epoch'), 'probe-new': ('probe', 'new_epoch'),
        'quiesce': ('quiesce', 'source_epoch'), 'freeze': ('freeze', 'source_epoch'),
        'restore': ('restore', 'source_epoch'), 'prepare': ('prepare', 'source_epoch'),
        'inspect-frozen': ('inspect-frozen', 'source_epoch'),
        'restore-recovery': ('restore-recovery', 'source_epoch'),
        'rejoin': ('rejoin', 'source_epoch'), 'activate-new': ('activate', 'new_epoch'),
        'inspect-cold': ('inspect-cold', 'current'),
        'prepare-recovery': ('prepare-recovery', 'current'),
    }

    def remote(self, label, action, payload=None, timeout=180):
        node = self.config['nodes'][label]
        try:
            wire_action, epoch_source = self._REMOTE_ACTIONS[action]
            epoch = (self.state.get(label, {}).get('epoch', self.operation['source_epoch'])
                     if epoch_source == 'current' else self.operation[epoch_source])
        except (KeyError, TypeError):
            raise ValueError('remote action has no fixed epoch authority') from None
        request = dict(action=wire_action, operation=self.operation['id'], epoch=epoch,
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

    def _installed_manifest(self, root, names, uid, gid, modes, hold=False):
        """Hash an exact fixed tree and optionally return its live authorities."""
        root = Path(root).absolute()
        trusted = {0, os.geteuid()}
        expected_files = set(names)
        expected_dirs = {str(Path(name).parent) for name in names} - {'.'}
        expected_dirs |= {str(parent) for name in names for parent in Path(name).parents
                          if str(parent) not in ('.', '')}
        held = []
        try:
            directory = descriptor.DescriptorAuthority.open_directory(
                root, trusted_root='/', trusted_uids=trusted)
            held.append(directory)
            found_files = set(); found_dirs = set(); stack = [('', directory)]
            while stack:
                prefix, current = stack.pop()
                for entry in os.listdir(current.directory_fd):
                    rel = str(Path(prefix) / entry) if prefix else entry
                    try:
                        child = descriptor.DescriptorAuthority.open_directory(
                            root / rel, trusted_root='/', trusted_uids=trusted)
                    except (NotADirectoryError, ValueError, OSError):
                        if rel not in expected_files:
                            raise ValueError('installed tree has unexpected entry')
                        found_files.add(rel)
                        continue
                    held.append(child)
                    found_dirs.add(rel)
                    stack.append((rel, child))
            if found_files != expected_files or found_dirs != expected_dirs:
                raise ValueError('installed tree is not exact')
            result = {}
            for name in names:
                mode = modes[name] if isinstance(modes, dict) else modes
                item = descriptor.DescriptorAuthority.open_file(
                    root/name, trusted_root='/', trusted_uids=trusted, expected_uid=uid,
                    expected_gid=gid, expected_mode=mode, expected_nlink=1,
                    limit=128 << 20)
                held.append(item)
                result[name] = item.sha256
            if hold:
                transferred, held = held, []
                return result, transferred
            return result
        finally:
            descriptor.close_all(held)

    def _recheck_installed_manifest(self, root, names, held):
        """Recheck held fixed inputs, including the exact child namespace."""
        root = Path(root).absolute()
        expected_files = set(names)
        expected_dirs = {str(Path(name).parent) for name in names} - {'.'}
        expected_dirs |= {str(parent) for name in names for parent in Path(name).parents
                          if str(parent) not in ('.', '')}
        directories = {}
        for authority in held:
            authority.recheck()
            try:
                relative = str(authority.path.relative_to(root))
            except ValueError:
                continue
            if authority._file_fd is None:
                relative = '' if relative == '.' else relative
                directories[relative] = authority
        if set(directories) != expected_dirs | {''}:
            raise ValueError('installed tree authorities are incomplete')
        expected_children = {relative: set() for relative in directories}
        for relative in expected_files:
            parent, name = str(Path(relative).parent), Path(relative).name
            expected_children['' if parent == '.' else parent].add(name)
        for relative in expected_dirs:
            if relative != '.':
                parent, name = str(Path(relative).parent), Path(relative).name
                expected_children['' if parent == '.' else parent].add(name)
        for relative, authority in directories.items():
            if set(os.listdir(authority.directory_fd)) != expected_children[relative]:
                raise ValueError('installed tree namespace changed')

    def _acceptance_request(self, phase, replica_config, positions, ledger, fault_ledger,
                            hold_installed=False):
        """Derive the canonical request from journal-authorized state, never callers."""
        import recovery
        has_fault = fault_ledger is not None
        profile, epoch, expected_position, reconciled = recovery.derive_restore_profile(self.operation, phase, has_fault)
        if reconciled:
            if self.journal.pending is not False:
                raise RuntimeError('reconciliation crossed the ordinary journal boundary')
            operation, _ = self.journal._boundary(self.operation['id'], expected_position)
            if operation != self.operation:
                raise RuntimeError('reconciliation operation differs')
            filename, action = ({
                'reconciled-compare': ('reconciliation.json', 'accept-checked-comparison'),
                'verification-baseline': ('verification-reconciliation.json', 'verification-only'),
            })[phase]
            raw, _ = _stable_private_bytes(self.work / filename)
            intent = recovery.parse_canonical_json(raw)
            if (not isinstance(intent, dict) or set(intent) != {'operation','action','failure_sha'}
                    or intent['operation'] != self.operation['id'] or intent['action'] != action
                    or not isinstance(intent['failure_sha'], str)
                    or not re.fullmatch('[0-9a-f]{64}', intent['failure_sha'])):
                raise RuntimeError('reconciliation intent differs')
            for suffix in ('request', 'result'):
                replay = self.work / (phase + '-acceptance-' + suffix + '.json')
                if replay.exists() or replay.is_symlink():
                    raise RuntimeError('reconciliation acceptance artifacts were already used')
        elif self.journal.pending is not True or self.journal.next != expected_position:
            raise RuntimeError('restore request is not at the locked journal boundary')
        if not isinstance(positions, dict) or set(positions) != {'main','session','aux'}:
            raise ValueError('invalid restore positions')
        ledger = Path(ledger).absolute()
        if ledger.name != ('new-writes.jsonl' if profile == 'fresh-writes' else 'ledger.jsonl'):
            raise ValueError('unexpected ledger name')
        account = pwd.getpwnam('hat-oracle')
        support_names, support, binaries = self._authorized_manifests()
        installed_holds = []
        try:
            support_result = self._installed_manifest(
            Path('/var/lib/hat-oracle/support'), support_names, 0, account.pw_gid,
            {name: 0o640 for name in support_names}, hold=hold_installed)
            if hold_installed:
                support_manifest, support_holds = support_result
                installed_holds.extend(support_holds)
            else:
                support_manifest = support_result
            if support_manifest != support:
                raise ValueError('installed oracle support differs')
            binary_result = self._installed_manifest(
                Path('/opt/hat-oracle/bin'), ('trail','litestream'), 0, 0, 0o755,
                hold=hold_installed)
            if hold_installed:
                binary_manifest, binary_holds = binary_result
                installed_holds.extend(binary_holds)
            else:
                binary_manifest = binary_result
            if binary_manifest != binaries:
                raise ValueError('installed oracle binaries differ')
            if profile == 'fresh-writes':
                try: selected, captured = self._fresh_writes
                except AttributeError:
                    raise ValueError('fresh ledger authority is unavailable') from None
                with descriptor.DescriptorAuthority.open_file(
                        self.work / 'new-writes-input-authority.json', trusted_root=self.work,
                        trusted_uids={0, os.geteuid()}, expected_uid=os.geteuid(), expected_mode=0o600,
                        expected_nlink=1, limit=1 << 20) as sidecar:
                    authority = recovery.parse_canonical_json(sidecar.read())
                recovery._authority(authority, self.operation, profile)
                selected.recheck(); identity = selected.identity
                wire = authority['ledger']
                if (authority != captured or wire['path'] != str(ledger) or wire['sha256'] != selected.sha256
                        or (wire['device'], wire['inode'], wire['mode'], wire['uid'], wire['links'], wire['bytes'])
                           != (identity[0], identity[1], stat.S_IMODE(identity[2]), identity[3], identity[5], identity[6])
                        or authority['support'] != support or authority['binaries'] != binaries):
                    raise ValueError('fresh ledger authority differs')
            else:
                authority = self._committed_preflight_authority()
                wire = authority['ledger']
                if wire['path'] != str(ledger) or authority['support'] != support or authority['binaries'] != binaries:
                    raise ValueError('protected ledger authority differs from committed preflight')
                with descriptor.DescriptorAuthority.open_file(
                        ledger, trusted_root='/', trusted_uids={0, os.geteuid()},
                        expected_uid=wire['uid'], expected_mode=wire['mode'],
                        expected_nlink=wire['links'], expected_size=wire['bytes'],
                        expected_sha256=wire['sha256'], limit=4 << 20) as selected:
                    identity = selected.identity
                    if ((identity[0], identity[1], stat.S_IMODE(identity[2]), identity[3], identity[5], identity[6])
                            != (wire['device'], wire['inode'], wire['mode'], wire['uid'], wire['links'], wire['bytes'])):
                        raise ValueError('protected ledger authority differs from committed preflight')
            inputs = {'replica_config_sha256': hashlib.sha256(replica_config.encode() if isinstance(replica_config,str) else bytes(replica_config)).hexdigest(), 'ledger_sha256': authority['ledger']['sha256'], 'ledger_authority': authority, 'restore_points': {db: {'source':'/var/lib/hat-demo/depot/data/'+db+'.db','position': positions[db]} for db in positions}, 'support': support, 'binaries': binaries}
            if profile == 'recovery-comparison':
                from client import read_closed_ledger
                events = read_closed_ledger(fault_ledger, self.operation['source_epoch'])
                operations = recovery.fault_operations(events)
                with descriptor.DescriptorAuthority.open_file(
                        fault_ledger, trusted_root='/', trusted_uids={0, os.geteuid()},
                        expected_uid=os.geteuid(), expected_mode=0o600, expected_nlink=1,
                        limit=4 << 20) as fault:
                    inputs.update(fault_ledger_sha256=fault.sha256, fault_operations=operations,
                                  fault_operation_count=len(operations),
                                  fault_operations_sha256=hashlib.sha256(recovery.canonical_json(operations)).hexdigest())
            request = {'schema': recovery._ACCEPTANCE_SCHEMA, 'operation': self.operation['id'], 'phase': phase, 'source': self.operation['source'], 'target': self.operation['target'], 'epoch': epoch, 'positions': positions, 'profile': profile, 'inputs': inputs}
            validated = recovery.validate_acceptance_request(request, self.operation)
            result = validated, recovery.canonical_json(request)
            return (*result, installed_holds, identity) if hold_installed else result
        except BaseException:
            if hold_installed:
                descriptor.close_all(installed_holds)
            if profile == 'fresh-writes': self._close_fresh_writes()
            raise

    def oracle(self, phase, replica_config, positions, selected_ledger, fault_ledger=None):
        """Run the independent oracle from a request derived after journal intent."""
        import recovery
        import node
        self.journal.check_authority()
        held = []; installed_holds = []
        try:
            request, request_bytes, installed_holds, ledger_identity = self._acceptance_request(
                phase, replica_config, positions, selected_ledger, fault_ledger, hold_installed=True)
            request_path = self.work / (phase + '-acceptance-request.json')
            self._durable_bytes(request_path, request_bytes, label='acceptance-request')
            if request['phase'] != phase or request['positions'] != positions:
                raise ValueError('restore request does not match locked phase')
            if (request['profile'] == 'recovery-comparison') != (fault_ledger is not None):
                raise ValueError('fault ledger does not match restore profile')
            config_raw = replica_config.encode() if isinstance(replica_config, str) else bytes(replica_config)
            if hashlib.sha256(config_raw).hexdigest() != request['inputs']['replica_config_sha256']:
                raise ValueError('replica configuration changed')
            authority = request['inputs']['ledger_authority']
            support_names = tuple(request['inputs']['support'])
            binary_names = tuple(request['inputs']['binaries'])
            ledger_path = Path(authority['ledger']['path'])
            if ledger_path.absolute() != Path(selected_ledger).absolute():
                raise ValueError('selected ledger differs from authority')
            identity = (ledger_identity[0], ledger_identity[1], stat.S_IMODE(ledger_identity[2]),
                        *ledger_identity[3:])
            if not ledger_path.is_absolute():
                raise ValueError('authorized ledger is unavailable')
            with descriptor.DescriptorAuthority.open_file(
                    ledger_path, trusted_root='/', trusted_uids={0, os.geteuid()},
                    expected_uid=authority['ledger']['uid'], expected_gid=identity[4],
                    expected_mode=authority['ledger']['mode'], expected_nlink=authority['ledger']['links'],
                    expected_size=authority['ledger']['bytes'], expected_sha256=authority['ledger']['sha256'],
                    limit=4 << 20) as authorized_ledger:
                if request['profile'] != 'fresh-writes':
                    recovery._protected_ledger(authorized_ledger.read())
            account = pwd.getpwnam('hat-oracle')
            prefix = 'd2' if (self.operation['source'], self.operation['target']) == ('A', 'B') else 'd3'
            area = Path('/var/lib/hat-oracle') / (prefix + '-' + self.operation['id'] + '-' + phase)
            oracle_directory(area); os.chown(area, 0, account.pw_gid)
            output = area / 'work'; output.mkdir(mode=0o700); os.chown(output, account.pw_uid, account.pw_gid)
            # The config is already an authorized raw byte value; write it only after all preflight checks.
            replica_path = area / 'replica.yml'
            self._durable_bytes(replica_path, config_raw, label='oracle-replica-config',
                                mode=0o640, uid=0, gid=account.pw_gid)
            self._reopen_exact_bytes(replica_path, config_raw, mode=0o640, uid=0, gid=account.pw_gid)
            # Support and binaries are fixed installed inputs; copying them would widen the trust boundary.
            self._copy_bound(ledger_path, area / 'ledger.jsonl', 0o600, 0, account.pw_gid,
                             authority['ledger']['sha256'], identity, label='oracle-ledger')
            oracle_fault = None
            if fault_ledger is not None:
                oracle_fault = area / 'fault-ledger.jsonl'
                self._copy_bound(fault_ledger, oracle_fault, 0o600, os.geteuid(), account.pw_gid,
                                 request['inputs']['fault_ledger_sha256'], label='oracle-fault-ledger')
            self._copy_bound(request_path, area / 'acceptance-request.json', 0o640, 0, account.pw_gid,
                             hashlib.sha256(request_bytes).hexdigest(), label='oracle-request')
            for directory in (area, output, self.work):
                fd=os.open(directory, os.O_RDONLY|os.O_DIRECTORY)
                try:
                    label = 'oracle-area.dir' if directory == area else ('oracle-output.dir' if directory == output else 'acceptance-work.dir')
                    self._fsync(fd, label, directory)
                finally: os.close(fd)
            result = output / 'result.json'
            unit = 'hat-' + prefix + '-' + self.operation['id'] + '-' + phase
            argv = ['systemd-run', '--unit='+unit, '--wait', '--collect', '--pipe',
                    '--property=User=hat-oracle', '--property=EnvironmentFile=/etc/hat-oracle/backup.env',
                    '--property=NoNewPrivileges=yes', '--property=RuntimeMaxSec=240', '--property=KillMode=control-group',
                    'python3', '/opt/hat-oracle/restore_baseline.py', '--root', str(output),
                    '--acceptance-request', str(area/'acceptance-request.json'), '--config', str(area/'replica.yml'),
                    '--ledger', str(area/'ledger.jsonl'), '--support', '/var/lib/hat-oracle/support',
                    '--binaries', '/opt/hat-oracle/bin', '--result', str(result)]
            if oracle_fault is not None: argv += ['--fault-ledger', str(oracle_fault)]
            expected = [(ledger_path, authority['ledger']['uid'], identity[4], 0o600, 4 << 20),
                        (area/'replica.yml', 0, account.pw_gid, 0o640, 1 << 20),
                        (area/'acceptance-request.json', 0, account.pw_gid, 0o640, 1 << 20)]
            if oracle_fault is not None: expected.append((oracle_fault, os.geteuid(), account.pw_gid, 0o600, 4 << 20))
            held = _open_held_inputs(expected, {0, os.geteuid(), account.pw_uid})
            self.command(argv, timeout=270)
            self._recheck_installed_manifest(
                Path('/var/lib/hat-oracle/support'), support_names, installed_holds)
            self._recheck_installed_manifest(
                Path('/opt/hat-oracle/bin'), binary_names, installed_holds)
            for item in held: item.recheck()
            with descriptor.DescriptorAuthority.open_file(
                    result, trusted_root='/', trusted_uids={0, account.pw_uid},
                    expected_uid=account.pw_uid, expected_gid=account.pw_gid,
                    expected_mode=0o600, expected_nlink=1, limit=4 << 20) as result_authority:
                result_raw = self._read_result(result_authority, result)
                events = None
                if request['profile'] == 'recovery-comparison':
                    # Reparse the controller-held sealed ledger independently of oracle output.
                    events = client.read_closed_ledger(fault_ledger, self.operation['source_epoch'])
                value = recovery.parse_acceptance_result(result_raw, request, self.operation)
                if events is not None:
                    recovery.validate_fault_outcomes(value['checks']['fault_outcomes'], events)
                retained = self.work / (phase + '-acceptance-result.json')
                self._copy_bound(result, retained, 0o600, account.pw_uid, os.getegid(),
                                 result_authority.sha256, label='retained-result')
                self._recheck_result(result_authority, result)
            for item in held: item.recheck()
            self._recheck_installed_manifest(
                Path('/var/lib/hat-oracle/support'), support_names, installed_holds)
            self._recheck_installed_manifest(
                Path('/opt/hat-oracle/bin'), binary_names, installed_holds)
            return value

        finally:
            fresh = getattr(self, '_fresh_writes', None)
            if fresh is not None:
                del self._fresh_writes
            descriptor.close_all(([fresh[0]] if fresh is not None else []) + installed_holds + held)

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
    import recovery
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
        ledger = work/'ledger.jsonl'
        io = ControlIO(journal, config, operation, work, state, maintenance, ingress)
        command = io.command
        remote = io.remote
        fence = io.fence
        close_ingress = io.close_ingress
        oracle = io.oracle
        def preflight():
            if socket.gethostname() != config['hostname']: raise ValueError('wrong controller')
            if maintenance.exists(): raise RuntimeError('ingress maintenance already set')
            state['A'] = remote('A','probe-source'); state['B'] = remote('B','probe-source')
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
                fd=os.open(ledger.parent,os.O_RDONLY|os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
            return {'source_boot':state['A']['boot_id'],'candidate_boot':state['B']['boot_id'],'identity':'matched',
                    'ledger_authority':io.capture_protected_authority(ledger, 'd2-preflight')}
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
            value=remote('B','activate-new')
            state['new']=remote('B','probe-new'); return value
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
            io.authorize_fresh_writes(fresh)
            deadline=time.monotonic()+90
            while True:
                value=remote('B','probe-new')
                if all(value['status']['positions'][db] > pos for db,pos in state['baseline']['positions'].items()): break
                if time.monotonic()>deadline: raise RuntimeError('new writes not confirmed published')
                time.sleep(1)
            evidence=oracle('new-writes',value['replica_config'],value['status']['positions'],fresh)
            return dict(writer='B',positions=value['status']['positions'],new_writes=evidence)
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
                io._durable_bytes(intent, recovery.canonical_json(dict(operation=reconcile,action='verification-only',failure_sha=hashlib.sha256(failure.read_bytes()).hexdigest())))
                close_ingress()
                fresh_fence=fence('inspect','offline')
                state['B']={'boot_id':previous['preflight']['candidate_boot']}
                current=remote('B','probe-new')
                if current['config']['role']!='writer' or not current['status']['trailbase_running']:raise RuntimeError('candidate writer changed')
                state['baseline']=previous['baseline']
                route_proof=previous['route'];digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
                if (route_proof['writer']!='B' or route_proof['epoch']!=operation['new_epoch'] or route_proof['config_sha']!=digest
                        or previous['baseline'].get('checks') != {'records':'PASS','authentication':'PASS'}):raise RuntimeError('recorded route/baseline changed')
                node.validate_support(Path('/var/lib/hat-oracle/support'),current['config']['support'])
                for binary,expected in current['config']['binaries'].items():
                    if hashlib.sha256((Path('/opt/hat-oracle/bin')/binary).read_bytes()).hexdigest()!=expected:raise RuntimeError('oracle release changed')
                baseline_recheck=oracle('verification-baseline',current['replica_config'],previous['baseline']['positions'],ledger)
                if (baseline_recheck['request']['phase'] != 'verification-baseline'
                        or baseline_recheck['request']['profile'] != 'baseline'
                        or baseline_recheck['request']['epoch'] != operation['new_epoch']
                        or baseline_recheck['request']['positions'] != previous['baseline']['positions']
                        or baseline_recheck['signature'] != previous['baseline']['signature']):
                    raise RuntimeError('verification baseline recheck differs')
                archived=work/'failure.before-verification.json'
                if archived.exists():raise RuntimeError('verification failure archive exists')
                failure.rename(archived)
                fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
                start_ingress(digest)
                value=verify();value['reconciliation_fence']=fresh_fence
                value['baseline_recheck'] = baseline_recheck
                journal.accept_verification(reconcile,value)
            elif reconcile:
                private_file(maintenance)
                if json.loads(maintenance.read_text())!={'operation':operation['id']}:raise RuntimeError('maintenance identity changed')
                failure=work/'failure.json'; private_file(failure)
                if json.loads(failure.read_text()).get('phase')!='compare':raise RuntimeError('unexpected failed phase')
                intent=work/'reconciliation.json'
                if intent.exists() or intent.is_symlink():raise RuntimeError('reconciliation already attempted')
                io._durable_bytes(intent, recovery.canonical_json(dict(operation=reconcile,action='accept-checked-comparison',failure_sha=hashlib.sha256(failure.read_bytes()).hexdigest())))
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
            probe = io.remote('A', 'probe-new')
            state['A'] = {'boot_id': expected_a_boot, 'positions': writer_probe(probe, expected_a_boot)}
            receipt = io.fence('power-on', 'running', label='B')
            if not isinstance(receipt, dict) or receipt.get('action') != 'power-on' or receipt.get('state') != 'running':
                raise RuntimeError('power-on receipt is not pinned')
            readiness = io.wait_reachable('B', timeout=90)
            cold = io.remote('B', 'inspect-cold')
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
            result = io.remote('B', 'rejoin', {'new_epoch': operation['new_epoch']})
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
                    result = io.remote('B', 'probe-new',
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
            final_a = io.remote('A', 'probe-new')
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
                current_a = io.remote('A', 'probe-new')
                state['A'] = {'boot_id': expected_a_boot, 'positions': writer_probe(current_a, expected_a_boot)}
                state['B'] = {'boot_id': retained['boot_id'], 'config_sha': retained['config_sha'],
                              'replica_sha': retained['replica_sha']}
                if io.remote('B', 'inspect-cold') != retained:
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
        fresh_a=io.remote('A','probe-new')
        status=fresh_a.get('status',{}); cfg=fresh_a.get('config',{})
        transition.validate_cut(status.get('positions'))
        if (fresh_a.get('boot_id')!=expected_boot or cfg.get('role')!='writer' or cfg.get('epoch')!=operation['new_epoch']
                or cfg.get('binaries')!=expected_config.get('binaries') or cfg.get('support')!=expected_config.get('support')
                or status.get('epoch')!=operation['new_epoch'] or status.get('healthy') is not True or status.get('trailbase_running') is not True):
            raise RuntimeError('A is not the retained healthy writer')
        fresh_provider=io.fence('inspect','running',label='B')
        state['B']={'boot_id':original_cold['boot_id']}
        fresh_cold=io.remote('B','inspect-cold')
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
