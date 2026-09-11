"""Direct durable-controller tests; no provider calls or live deployment mutations."""
import ast
import importlib.util
import datetime
from contextlib import closing
import json
import hashlib
import os
import signal
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests.acceptance_fixtures import acceptance_result

ENTRY = Path(os.environ.get('HAT_CONTROL_ENTRY', str(Path(__file__).resolve().parents[1]/'hat/control.py')))

def load():
    sys.path.insert(0,str(ENTRY.parent))
    spec = importlib.util.spec_from_file_location('hat_control', ENTRY)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

class TransitionTests(unittest.TestCase):
    def module(self):
        self.assertTrue(ENTRY.is_file(), 'missing operational controller journal')
        return load()

    def test_intent_is_committed_before_action_and_history_is_retained(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with m.Journal(root) as journal:
                operation = journal.begin('A', 'B', 'd1-original')
                self.assertNotEqual(operation['new_epoch'], 'd1-original')
                for phase in m.PHASES:
                    def action():
                        with closing(sqlite3.connect(root/'journal.db')) as reader:
                            last = reader.execute('SELECT phase, status FROM steps ORDER BY rowid DESC LIMIT 1').fetchone()
                        self.assertEqual(last, (phase, 'intent'))
                        return {'checked': True}
                    journal.step(phase, action)
                journal.finish()
                other = journal.begin('B', 'A', operation['new_epoch'])
                self.assertNotEqual(other['new_epoch'], operation['new_epoch'])
                with closing(sqlite3.connect(root/'journal.db')) as reader:
                    self.assertEqual(reader.execute('SELECT count(*) FROM steps').fetchone()[0], 2*len(m.PHASES))

    def test_concurrency_and_phase_skipping_refuse_before_action(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with m.Journal(root) as journal:
                with self.assertRaises((BlockingIOError, RuntimeError)):
                    with m.Journal(root): pass
                journal.begin('A', 'B', 'd1-original')
                called = []
                with self.assertRaises(RuntimeError): journal.step('route', lambda: called.append(True))
                with self.assertRaises(RuntimeError): journal.finish()
                self.assertEqual(called, [])

    def test_failed_action_cannot_be_retried_or_reopened_as_new_operation(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with m.Journal(root) as journal:
                journal.begin('A', 'B', 'd1-original')
                def fail(): raise RuntimeError('external outcome unknown')
                with self.assertRaises(RuntimeError): journal.step('preflight', fail)
                with self.assertRaises(RuntimeError): journal.step('preflight', lambda: {})
            with m.Journal(root) as journal:
                with self.assertRaises(RuntimeError): journal.begin('A', 'B', 'd1-original')

    def test_process_death_leaves_durable_unfinished_intent(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            child = subprocess.run([sys.executable, __file__, '--crash', str(root)], timeout=10)
            self.assertEqual(child.returncode, 23)
            with m.Journal(root) as journal:
                with self.assertRaises(RuntimeError): journal.begin('A', 'B', 'd1-original')
            with closing(sqlite3.connect(root/'journal.db')) as reader:
                self.assertEqual(reader.execute('SELECT phase,status FROM steps').fetchall(), [('preflight','intent')])

    def test_explicit_comparison_reconciliation_preserves_intents_and_epoch(self):
        m=self.module()
        self.assertTrue(hasattr(m.Journal,'accept_comparison'), 'missing bounded comparison reconciliation')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();cut=dict(main=1,session=2,aux=3);signature={k:'a'*64 for k in cut}
            with m.Journal(root) as j:
                op=j.begin('A','B','d1-old')
                for phase in m.PHASES[:5]: j.step(phase,lambda:dict(cut=cut,signature=signature))
                def fail(): raise RuntimeError('oracle permissions')
                with self.assertRaises(RuntimeError): j.step('compare',fail)
                before=j.db.execute('SELECT * FROM steps ORDER BY rowid').fetchall()
            with m.Journal(root) as j:
                with self.assertRaises(RuntimeError):j.comparison_boundary('b'*32)
                value=acceptance_result(op,'compare',cut,signature)
                changed=json.loads(json.dumps(value));changed['request']['positions']['main']=2
                with self.assertRaises(ValueError):j.accept_comparison(op['id'],changed)
                j.accept_comparison(op['id'],value)
                self.assertEqual(j.operation,op);self.assertEqual(j.next,6)
                self.assertEqual(j.db.execute('SELECT * FROM steps ORDER BY rowid').fetchall()[:-1],before)
                with self.assertRaises(RuntimeError):j.accept_comparison(op['id'],value)
                with self.assertRaises(RuntimeError):j.step('fence',lambda:{})
                for phase in m.PHASES[6:]:j.step(phase,lambda:{})
                j.finish()
                self.assertEqual(j.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)

    def test_verification_only_completion_preserves_previous_steps(self):
        m=self.module()
        self.assertTrue(hasattr(m.Journal,'accept_verification'),'missing verification-only reconciliation')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();cut=dict(main=1,session=1,aux=1);newcut=dict(main=2,session=2,aux=2)
            with m.Journal(root) as j:
                op=j.begin('A','B','d1-old')
                for phase in m.PHASES[:9]:j.step(phase,lambda:{'positions':cut})
                def fail():raise RuntimeError('listener not ready')
                with self.assertRaises(RuntimeError):j.step('verify',fail)
                before=j.db.execute('SELECT * FROM steps ORDER BY rowid').fetchall()
            with m.Journal(root) as j:
                with self.assertRaises(RuntimeError):j.comparison_boundary(op['id'])
                result=dict(writer='B',epoch=op['new_epoch'],positions=newcut,
                            new_writes=acceptance_result(op,'new-writes',newcut))
                for patch in ({'epoch':'d1-wrong'},{'positions':cut},{'new_writes':{'auth_and_records':'FAIL'}}):
                    with self.assertRaises(ValueError):j.accept_verification(op['id'],result|patch)
                j.accept_verification(op['id'],result)
                self.assertEqual(j.db.execute('SELECT * FROM steps ORDER BY rowid').fetchall()[:-1],before)
                with self.assertRaises(RuntimeError):j.accept_verification(op['id'],result)
                j.finish();self.assertEqual(j.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)

    def test_unrecognized_existing_database_is_not_reinitialized(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); path = root/'journal.db'
            with closing(sqlite3.connect(path)) as db: db.execute('CREATE TABLE unrelated(id INTEGER)')
            path.chmod(0o600); before = path.read_bytes()
            with self.assertRaises((ValueError, RuntimeError)):
                with m.Journal(root): pass
            self.assertEqual(path.read_bytes(), before)

    def test_exact_legacy_journal_migrates_and_new_rows_select_restore_contract(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'journal.db'
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''
                    CREATE TABLE operations (
                        id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                        source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
                        complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
                    CREATE UNIQUE INDEX one_unfinished ON operations(complete) WHERE complete=0;
                    CREATE TABLE steps (
                        operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
                        phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
                        evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status));
                ''')
            path.chmod(0o600)
            with m.Journal(root) as journal:
                columns=[row[1] for row in journal.db.execute('PRAGMA table_info(operations)')]
                self.assertEqual(columns,['id','source','target','source_epoch','new_epoch','complete','restore_contract'])
                self.assertEqual(journal.db.execute('PRAGMA journal_mode').fetchone(),('delete',))
                self.assertEqual(journal.db.execute('PRAGMA synchronous').fetchone(),(3,))
                operation=journal.begin('A','B','d1-original')
                self.assertEqual(journal.db.execute('SELECT restore_contract FROM operations WHERE id=?',(operation['id'],)).fetchone(),('hat-restore-acceptance-1',))
            self.assertFalse((root/'journal.db-wal').exists());self.assertFalse((root/'journal.db-shm').exists())
            with m.Journal(root): pass

    def test_populated_legacy_unknown_phase_refuses_before_alter(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); path=root/'journal.db'
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''
                    CREATE TABLE operations (id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                        source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
                        complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
                    CREATE UNIQUE INDEX one_unfinished ON operations(complete) WHERE complete=0;
                    CREATE TABLE steps (operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
                        phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
                        evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status));
                    INSERT INTO operations VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','A','B','d1-old','d1-new',1);
                    INSERT INTO steps VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,'unknown','intent','{}');
                ''')
            path.chmod(0o600); before=path.read_bytes()
            with self.assertRaises(ValueError):
                with m.Journal(root): pass
            self.assertEqual(path.read_bytes(),before)

    def test_populated_legacy_validation_rejects_each_malformed_shape_before_alter(self):
        m=self.module()
        def make(root, mutation):
            path=root/'journal.db'; ident='b'*32; source_epoch='d1-old'; new_epoch='d1-'+ident
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''
                    CREATE TABLE operations (id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                        source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
                        complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
                    CREATE UNIQUE INDEX one_unfinished ON operations(complete) WHERE complete=0;
                    CREATE TABLE steps (operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
                        phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
                        evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status));
                ''')
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)',(ident,'A','B',source_epoch,new_epoch,1))
                for position,phase in enumerate(m.PHASES):
                    db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,position,phase,'intent','{}'))
                    evidence=json.dumps({'writer':'B','epoch':new_epoch,'config_sha':'0'*64}) if phase=='route' else '{}'
                    db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(ident,position,phase,'done',evidence))
                if mutation=='non-latest':
                    old='a'*32; db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)',(old,'A','B','d1-bad','d1-'+old,1))
                elif mutation=='id': db.execute('UPDATE operations SET id=? WHERE id=?',('bad',ident))
                elif mutation=='source-epoch': db.execute('UPDATE operations SET source_epoch=? WHERE id=?',('bad',ident))
                elif mutation=='new-epoch': db.execute('UPDATE operations SET new_epoch=? WHERE id=?',('d1-'+'c'*32,ident))
                elif mutation=='zero-steps': db.execute('DELETE FROM steps WHERE operation=?',(ident,))
                elif mutation=='duplicate-done': db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase='route' AND status='done'",('{"writer":"B","writer":"A"}',ident))
                elif mutation=='non-object-done': db.execute("UPDATE steps SET evidence='[]' WHERE operation=? AND phase='route' AND status='done'",(ident,))
                db.commit()
            path.chmod(0o600); return path

        for mutation in ('non-latest','id','source-epoch','new-epoch','zero-steps','duplicate-done','non-object-done'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve(); path=make(root,mutation); before=path.read_bytes()
                with self.assertRaises((ValueError,RuntimeError,sqlite3.Error)):
                    with m.Journal(root): pass
                self.assertEqual(path.read_bytes(),before)
                with closing(sqlite3.connect(path)) as db:
                    self.assertNotIn('restore_contract',[row[1] for row in db.execute('PRAGMA table_info(operations)')])

        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); path=make(root,'non-latest'); before=path.read_bytes()
            ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
            self.assertFalse(m.ingress_allowed(root,root/'maintenance',root/'permit',ingress,'boot'))
            self.assertEqual(path.read_bytes(),before)
            with closing(sqlite3.connect(path)) as db:
                self.assertNotIn('restore_contract',[row[1] for row in db.execute('PRAGMA table_info(operations)')])

    def test_interrupted_legacy_migration_reopens_as_exact_old_then_new_schema(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'journal.db'
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''
                    CREATE TABLE operations (id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL,
                        source_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
                        complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
                    CREATE UNIQUE INDEX one_unfinished ON operations(complete) WHERE complete=0;
                    CREATE TABLE steps (operation TEXT NOT NULL REFERENCES operations(id), position INTEGER NOT NULL,
                        phase TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('intent','done')),
                        evidence TEXT NOT NULL, PRIMARY KEY(operation,position,status));
                ''')
                db.execute('BEGIN IMMEDIATE')
                db.execute("ALTER TABLE operations ADD COLUMN restore_contract TEXT NOT NULL DEFAULT 'legacy' CHECK(restore_contract IN ('legacy','hat-restore-acceptance-1'))")
                # Closing without commit simulates interruption; SQLite must roll back to exact legacy.
            path.chmod(0o600)
            with m.Journal(root) as journal:
                self.assertEqual([r[1] for r in journal.db.execute('PRAGMA table_info(operations)')][-1],'restore_contract')
            with m.Journal(root): pass

    def test_unknown_journal_schema_index_contract_and_wal_refuse(self):
        m=self.module()
        for case in ('table','index','contract','wal'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve()
                with m.Journal(root): pass
                path=root/'journal.db'
                with closing(sqlite3.connect(path)) as db:
                    if case=='table': db.execute('CREATE TABLE extra(value TEXT)')
                    elif case=='index': db.execute('CREATE INDEX extra_index ON steps(phase)')
                    elif case=='contract':
                        db.execute('PRAGMA ignore_check_constraints=ON')
                        db.execute("INSERT INTO operations VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','A','B','d1-old','d1-new',1,'unknown')")
                    db.commit()
                if case=='wal':
                    (root/'journal.db-wal').write_bytes(b'unknown');(root/'journal.db-wal').chmod(0o600)
                before=path.read_bytes()
                with self.assertRaises((ValueError,RuntimeError,OSError,sqlite3.Error)):
                    with m.Journal(root): pass
                self.assertEqual(path.read_bytes(),before)

    def test_operations_sql_reference_inventory_is_explicit(self):
        tree=ast.parse(ENTRY.read_text());found=set()
        class Scan(ast.NodeVisitor):
            def __init__(self):self.classes=[];self.functions=[]
            def visit_ClassDef(self,node):
                self.classes.append(node.name);self.generic_visit(node);self.classes.pop()
            def visit_FunctionDef(self,node):
                self.functions.append(node.name)
                if any(isinstance(item,ast.Constant) and isinstance(item.value,str) and 'operations' in item.value.lower()
                       for item in ast.walk(node)):
                    found.add('.'.join(self.classes+self.functions))
                self.generic_visit(node);self.functions.pop()
        Scan().visit(tree)
        self.assertEqual(found,{
            'Journal.__enter__','Journal.begin','Journal.step','Journal._boundary',
            'Journal.continue_rejoin','Journal.finish','_journal_schema','_check_constraints','_check_indexes','_d3_serving_state',
            'current_writer','_ingress_allowed_body','_validate_legacy_rows','reconcile_existing',
        })

    def test_unfinished_legacy_contract_refuses_step_boundaries_accept_and_finish(self):
        m=self.module()
        for case in ('step','compare','verify','finish'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();called=[]
                with m.Journal(root) as journal:
                    operation=journal.begin('A','B','d1-old')
                    if case=='step':
                        journal.db.execute("UPDATE operations SET restore_contract='legacy' WHERE id=?",(operation['id'],));journal.db.commit()
                        with self.assertRaises(RuntimeError):journal.step('preflight',lambda:called.append(True))
                        self.assertEqual(called,[]);continue
                    boundary=5 if case=='compare' else 9 if case=='verify' else len(m.PHASES)
                    for position,phase in enumerate(m.PHASES[:boundary]):
                        journal.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(operation['id'],position,phase,'intent','{}'))
                        journal.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(operation['id'],position,phase,'done','{}'))
                    if boundary<len(m.PHASES):
                        journal.db.execute('INSERT INTO steps VALUES(?,?,?,?,?)',(operation['id'],boundary,m.PHASES[boundary],'intent','{}'))
                    journal.db.execute("UPDATE operations SET restore_contract='legacy' WHERE id=?",(operation['id'],));journal.db.commit()
                    journal.operation=operation;journal.next=boundary;journal.pending=boundary<len(m.PHASES)
                    if case=='compare':
                        for call in (lambda:journal.comparison_boundary(operation['id']),lambda:journal.accept_comparison(operation['id'],{})):
                            with self.assertRaises(RuntimeError):call()
                    elif case=='verify':
                        for call in (lambda:journal.verification_boundary(operation['id']),lambda:journal.accept_verification(operation['id'],{})):
                            with self.assertRaises(RuntimeError):call()
                    else:
                        journal.pending=False
                        with self.assertRaises(RuntimeError):journal.finish()

    def test_canonical_ddl_ignores_formatting_and_comments_but_preserves_literals(self):
        m=self.module()
        self.assertEqual(m._canonical_ddl('CREATE /*x*/ TABLE [Operations] ("ID" TEXT CHECK(status IN (\'intent\',\'done\')))'),
                         "createtableoperations(idtextcheck(statusin('intent','done')))")
        self.assertNotEqual(m._canonical_ddl("CHECK(x='A')"), m._canonical_ddl("CHECK(x='a')"))

    def test_semantic_schema_rejects_extra_objects_constraint_differences_and_corruption(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            with m.Journal(root): pass
            path=root/'journal.db'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE extra(value TEXT)'); db.commit()
            with self.assertRaises((ValueError,RuntimeError)): 
                with m.Journal(root): pass
            path.unlink()
            for suffix in ('-journal','-wal','-shm'):
                p=root/('journal.db'+suffix)
                if p.exists():p.unlink()
            with m.Journal(root): pass
            with closing(sqlite3.connect(path)) as db:
                db.execute("UPDATE operations SET complete=2") if False else None
                db.execute('PRAGMA writable_schema=ON')
                db.execute("UPDATE sqlite_schema SET sql=replace(sql,'CHECK(complete IN (0,1))','CHECK(complete IN (0,2))') WHERE name='operations'")
                db.commit()
            with self.assertRaises((ValueError,RuntimeError)):
                with m.Journal(root): pass

    def test_semantic_schema_integrity_and_foreign_key_checks_run_on_open(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            with m.Journal(root) as journal:
                op=journal.begin('A','B','d1-old')
                journal.db.execute("PRAGMA writable_schema=ON")
                journal.db.execute("UPDATE sqlite_schema SET sql=replace(sql,'source TEXT','source BLOB') WHERE name='operations'")
                journal.db.commit()
            with self.assertRaises((ValueError,RuntimeError)):
                with m.Journal(root): pass

    def test_ingress_snapshot_finalizer_rejects_interleaving_for_empty_and_completed(self):
        m=self.module()
        cases=('no-journal','empty','completed')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
                maintenance=root/'maintenance'; permit=root/'permit'
                if case == 'empty':
                    with m.Journal(root): pass
                elif case == 'completed':
                    digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
                    with m.Journal(root) as journal:
                        operation=journal.begin('A','B','d1-old')
                        for phase in m.PHASES:
                            evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                            journal.step(phase,lambda evidence=evidence:evidence)
                        journal.finish()
                args=(root,maintenance,permit,ingress,'boot')
                self.assertTrue(m.ingress_allowed(*args))
                for suffix in ('-wal','-shm','-journal'):
                    def mutate(suffix=suffix): (root/('journal.db'+suffix)).write_bytes(b'x')
                    m._INGRESS_PRE_FINALIZE_HOOK=mutate
                    try: self.assertFalse(m.ingress_allowed(*args),suffix)
                    finally: m._INGRESS_PRE_FINALIZE_HOOK=None
                def mutate_ingress(): ingress.write_bytes(ingress.read_bytes()+b'x')
                m._INGRESS_PRE_FINALIZE_HOOK=mutate_ingress
                try: self.assertFalse(m.ingress_allowed(*args))
                finally: m._INGRESS_PRE_FINALIZE_HOOK=None

    def test_ingress_allowed_rejects_journal_or_config_replacement_during_read(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n'); maintenance=root/'maintenance'
            with m.Journal(root) as journal:
                op=journal.begin('A','B','d1-old')
                for phase in m.PHASES:
                    ev={'writer':'B','epoch':op['new_epoch'],'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()} if phase=='route' else {}
                    journal.step(phase,lambda ev=ev:ev)
                journal.finish()
            original=ingress.read_bytes(); ingress.write_bytes(original+b'changed')
            self.assertFalse(m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))
            ingress.write_bytes(original)
            replacement=root/'replacement'; replacement.write_bytes((root/'journal.db').read_bytes()); replacement.chmod(0o600)
            (root/'journal.db').replace(root/'journal.db.old'); replacement.replace(root/'journal.db')
            # Identical-byte replacement before a lockless read has no trusted baseline identity; the
            # implementation must cover replacement during the read via pre/post descriptor checks.
            self.assertTrue(m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))

    def test_fence_requires_exact_target_fresh_completed_observations(self):
        m = self.module()
        self.assertTrue(hasattr(m,'validate_fence'), 'missing completed fencing gate')
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = now.isoformat(); target = {'node':'A','instance_id':42,'provider_label':'demo','address':'192.0.2.1'}
        observation = {'time':stamp,'state':'offline','identity':{'instance_id':42,'provider_label':'demo','addresses':['192.0.2.1']}}
        receipt = dict(action='power-off',target=target,request={'id':'request','time':stamp},completion={'time':stamp},state='offline',observations=[observation,observation])
        m.validate_fence(receipt,target,'power-off','offline',now.timestamp()-1)
        for patch in [dict(state='running'),dict(target={'node':'B','instance_id':43}),dict(observations=[]),dict(observations=[observation,observation | {'identity':{'instance_id':43,'provider_label':'demo','addresses':['192.0.2.1']}}]),dict(completion={'time':(now-datetime.timedelta(hours=1)).isoformat()})]:
            with self.assertRaises(ValueError): m.validate_fence(receipt | patch,target,'power-off','offline',now.timestamp()-1)

    def test_route_moves_app_and_home_only_to_selected_writer(self):
        m = self.module()
        self.assertTrue(hasattr(m,'route_to_b'), 'missing fixed route change')
        config = (Path(__file__).resolve().parents[1]/'deploy/haproxy.cfg').read_text() if 'HAT_CONTROL_ENTRY' not in os.environ else (ENTRY.parent/'haproxy.cfg').read_text()
        changed = m.route_to_b(config)
        self.assertIn('server b 127.0.0.1:14003 check',changed)
        self.assertNotIn('server a 127.0.0.1:14000 check',changed)
        self.assertIn('backend home\n    server b 127.0.0.1:14002 check',changed)
        with self.assertRaises(ValueError): m.route_to_b(changed)

    def test_route_crash_denies_restart_and_reconciles_ingress_before_refusal(self):
        m = self.module()
        self.assertTrue(hasattr(m,'ingress_allowed'), 'missing interrupted-route gate')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            child=subprocess.Popen([sys.executable,__file__,'--crash-route',str(root)],stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'ready')
                args=(root,root/'maintenance',root/'permit',root/'proxy.cfg','boot')
                self.assertEqual(m.ingress_allowed(*args),m.process_identity(child.pid) is not None)
                self.assertFalse(m.ingress_allowed(*args[:-1],'new-boot'))
                child.kill();child.wait()
                self.assertFalse(m.ingress_allowed(*args))
                with m.Journal(root) as journal:
                    with self.assertRaises(RuntimeError):
                        m.reconcile_existing(journal,root/'maintenance',lambda:(root/'serving').unlink(),root/'proxy.cfg')
                self.assertFalse((root/'serving').exists())
                self.assertTrue((root/'maintenance').exists())
            finally:
                if child.poll() is None: child.kill();child.wait()
                child.stdout.close()

    def test_completed_crash_reconciles_exact_marker_without_new_operation(self):
        m = self.module()
        self.assertTrue(hasattr(m,'reconcile_existing'), 'missing completion-window reconciliation')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            p=subprocess.run([sys.executable,__file__,'--crash-completed',str(root)],timeout=10)
            self.assertEqual(p.returncode,24)
            args=(root,root/'maintenance',root/'permit',root/'proxy.cfg','boot')
            self.assertFalse(m.ingress_allowed(*args))
            with m.Journal(root) as journal:
                self.assertTrue(m.reconcile_existing(journal,root/'maintenance',lambda:None,root/'proxy.cfg'))
                self.assertEqual(journal.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)
            self.assertFalse((root/'maintenance').exists())
            self.assertTrue(m.ingress_allowed(*args))

    def test_oracle_directory_remains_group_searchable_under_private_umask(self):
        m = self.module()
        self.assertTrue(hasattr(m,'oracle_directory'), 'missing explicit oracle directory permissions')
        with tempfile.TemporaryDirectory() as tmp:
            area=Path(tmp)/'oracle'; old=os.umask(0o077)
            try: m.oracle_directory(area)
            finally: os.umask(old)
            self.assertEqual(area.stat().st_mode & 0o777,0o750)

    def test_unsafe_files_and_lost_lock_refuse(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); other = root/'other'; other.write_text('preserve')
            (root/'journal.db').symlink_to(other)
            with self.assertRaises((ValueError, RuntimeError, OSError)):
                with m.Journal(root): pass
            self.assertEqual(other.read_text(), 'preserve')
            (root/'journal.db').unlink()
            with m.Journal(root) as journal:
                journal.begin('A', 'B', 'd1-original')
                (root/'controller.lock').rename(root/'retained.lock')
                (root/'controller.lock').touch(mode=0o600)
                with self.assertRaises(RuntimeError): journal.step('preflight', lambda: {})

if __name__ == '__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--crash-completed':
        m=load();root=Path(sys.argv[2]);(root/'proxy.cfg').write_text('route B\n')
        digest=hashlib.sha256((root/'proxy.cfg').read_bytes()).hexdigest()
        with m.Journal(root) as journal:
            op=journal.begin('A','B','d1-original')
            (root/'maintenance').write_text(json.dumps({'operation':op['id']}));(root/'maintenance').chmod(0o600)
            for phase in m.PHASES:
                evidence={'writer':'B','epoch':op['new_epoch'],'config_sha':digest} if phase=='route' else {}
                journal.step(phase,lambda evidence=evidence:evidence)
            journal.finish();os._exit(24)
    elif len(sys.argv)==3 and sys.argv[1]=='--crash-route':
        m=load();root=Path(sys.argv[2])
        with m.Journal(root) as journal:
            op=journal.begin('A','B','d1-original')
            def publish():
                (root/'proxy.cfg').write_text('route B\n')
                (root/'serving').touch()
                (root/'maintenance').write_text(json.dumps({'operation':op['id']}))
                permit=dict(operation=op['id'],boot_id='boot',pid=os.getpid(),birth=m.process_identity(os.getpid()),config_sha=hashlib.sha256((root/'proxy.cfg').read_bytes()).hexdigest())
                (root/'permit').write_text(json.dumps(permit));(root/'permit').chmod(0o600)
                print('ready',flush=True)
                while True: signal.pause()
            for phase in m.PHASES:
                journal.step(phase,publish if phase=='route' else lambda:{})
    elif len(sys.argv) == 3 and sys.argv[1] == '--crash':
        with load().Journal(Path(sys.argv[2])) as journal:
            journal.begin('A', 'B', 'd1-original')
            journal.step('preflight', lambda: os._exit(23))
    else: unittest.main()
