"""Direct durable-controller tests; no provider calls or live deployment mutations."""
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
                value=dict(positions=cut,signature=signature,auth_and_records='PASS')
                with self.assertRaises(ValueError):j.accept_comparison(op['id'],value|{'positions':dict(main=2,session=2,aux=3)})
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
                result=dict(writer='B',epoch=op['new_epoch'],positions=newcut,new_writes=dict(positions=newcut,auth_and_records='PASS'))
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
