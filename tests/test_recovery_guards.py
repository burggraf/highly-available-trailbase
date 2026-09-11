"""Local D3 journal, route, and ingress guard contracts; no live actions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ENTRY = Path(os.environ.get('HAT_CONTROL_ENTRY', str(Path(__file__).resolve().parents[1]/'hat/control.py')))
D2 = ('preflight','close_ingress','quiesce','fence','freeze','compare','activate','baseline','route','verify')
D3 = ('preflight','close_ingress','fence','select_cut','restore','compare','activate','baseline','route','verify','rejoin_boot','rejoin','verify_redundancy')


def load():
    sys.path.insert(0, str(ENTRY.parent))
    spec = importlib.util.spec_from_file_location('hat_control_d3', ENTRY)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class RecoveryGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load()

    def _d3(self, root, count=10, verify_writer='A'):
        ingress = root/'proxy.cfg'; ingress.write_text('route A\n')
        digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
        journal = self.m.Journal(root).__enter__()
        operation = journal.begin('B','A','d1-current')
        cut={'main':10,'session':20,'aux':30};baseline={db:1 for db in cut};fresh={db:2 for db in cut}
        signature={db:hashlib.sha256(('cut-'+db).encode()).hexdigest() for db in cut}
        baseline_signature={db:hashlib.sha256(('baseline-'+db).encode()).hexdigest() for db in cut}
        fresh_signature={db:hashlib.sha256(('fresh-'+db).encode()).hexdigest() for db in cut}
        evidence={
            'preflight':{},'close_ingress':{},'fence':{},
            'select_cut':{'positions':cut},
            'restore':{'cut':cut,'signature':signature},
            'compare':{'positions':cut,'signature':signature,'auth_and_records':'PASS'},
            'activate':{},
            'baseline':{'epoch':operation['new_epoch'],'positions':baseline,'signature':baseline_signature,'auth_and_records':'PASS'},
            'route':{'writer':'A','epoch':operation['new_epoch'],'config_sha':digest},
            'verify':{'writer':verify_writer,'epoch':operation['new_epoch'],'positions':fresh,
                      'new_writes':{'positions':fresh,'signature':fresh_signature,'auth_and_records':'PASS'}},
        }
        for phase in D3[:count]: journal.step(phase, lambda phase=phase: evidence[phase])
        return journal, operation, ingress

    def _maintenance(self, root, operation):
        path = root/'maintenance'; path.write_text(json.dumps({'operation':operation['id']})); path.chmod(0o600)
        return path

    def test_direction_selects_exact_phase_plan_and_finish_length(self):
        self.assertEqual(self.m.PHASES, D2)
        self.assertEqual(self.m.phase_plan('A','B'), D2)
        self.assertEqual(self.m.phase_plan('B','A'), D3)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.m.Journal(root) as journal:
                operation = journal.begin('B','A','d1-current')
                called=[]
                with self.assertRaises(RuntimeError): journal.step('quiesce', lambda: called.append(True))
                for phase in D3: journal.step(phase, lambda: {})
                journal.finish()
                self.assertEqual(called, [])
                rows=journal.db.execute('SELECT phase,status FROM steps WHERE operation=? ORDER BY rowid',(operation['id'],)).fetchall()
                self.assertEqual(rows, [(phase,status) for phase in D3 for status in ('intent','done')])

    def test_rejoin_continuation_accepts_only_unused_verified_d3_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); journal,operation,_=self._d3(root)
            journal.__exit__(None,None,None)
            with self.m.Journal(root) as journal:
                resumed, evidence = journal.continue_rejoin(operation['id'])
                self.assertEqual(resumed, operation); self.assertEqual(journal.next, 10)
                self.assertEqual(evidence['verify']['writer'], 'A')
                with self.assertRaises(RuntimeError): journal.continue_rejoin(operation['id'])
                with self.assertRaises(RuntimeError): journal.continue_rejoin('f'*32)
                with self.assertRaises(RuntimeError): journal.step('rejoin', lambda: {})
                with self.assertRaises(RuntimeError): journal.step('rejoin_boot', lambda: (_ for _ in ()).throw(RuntimeError('failed')))
            with self.m.Journal(root) as journal:
                with self.assertRaises(RuntimeError): journal.continue_rejoin(operation['id'])

    def test_route_rewrite_is_exact_and_reversible_for_configured_endpoints(self):
        endpoints={'A':{'writer':'127.0.0.1:1','home':'127.0.0.1:2'},'B':{'writer':'127.0.0.1:3','home':'127.0.0.1:4'}}
        original='backend writer\n    server a 127.0.0.1:1 check\n\nbackend home\n    server a 127.0.0.1:2 check\n\nbackend status_b\n    server b 127.0.0.1:4 check\n'
        changed=self.m.route_to(original,'A','B',endpoints)
        self.assertIn('backend writer\n    server b 127.0.0.1:3 check',changed)
        self.assertIn('backend home\n    server b 127.0.0.1:4 check',changed)
        self.assertEqual(self.m.route_to(changed,'B','A',endpoints),original)
        with self.assertRaises(ValueError):self.m.route_to(changed,'A','B',endpoints)
        with self.assertRaises(ValueError):self.m.route_to(original+'backend home\n    server a 127.0.0.1:2 check\n','A','B',endpoints)

    def test_current_writer_comes_from_completed_operation_and_exact_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\n')
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-stale-install')
                for phase in D2:
                    evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                    journal.step(phase,lambda evidence=evidence:evidence)
                journal.finish()
                self.assertEqual(self.m.current_writer(journal,ingress),{'operation':operation['id'],'writer':'B','epoch':operation['new_epoch']})
                unfinished=journal.begin('B','A',operation['new_epoch'])
                with self.assertRaises(RuntimeError):self.m.current_writer(journal,ingress)
                journal.db.execute('DELETE FROM operations WHERE id=?',(unfinished['id'],));journal.db.commit();journal.operation=None
                journal.db.execute("UPDATE steps SET evidence='{}' WHERE operation=? AND phase='route' AND status='done'",(operation['id'],));journal.db.commit()
                with self.assertRaises(RuntimeError):self.m.current_writer(journal,ingress)

    def test_completed_route_authority_requires_exact_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-current')
                for phase in D2:
                    evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                    journal.step(phase,lambda evidence=evidence:evidence)
                journal.finish()
            route=root/'journal.db'
            mutations=({'writer':'A','epoch':operation['new_epoch'],'config_sha':digest},
                       {'writer':'B','epoch':'wrong','config_sha':digest},
                       {'writer':'B','epoch':operation['new_epoch']},
                       {'writer':'B','epoch':operation['new_epoch'],'config_sha':digest,'extra':1})
            for value in mutations:
                with self.subTest(value=value), self.m.Journal(root) as journal:
                    journal.db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase='route' AND status='done'",(json.dumps(value) if not isinstance(value,str) else value,operation['id'])); journal.db.commit()
                    with self.assertRaises(RuntimeError): self.m.current_writer(journal,ingress)
                    self.assertFalse(self.m.ingress_allowed(root,root/'missing',root/'missing',ingress,'boot'))

    def test_completed_route_authority_rejects_malformed_and_stale_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-current')
                for phase in D2:
                    evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                    journal.step(phase,lambda evidence=evidence:evidence)
                journal.finish()
            for value in ('{not-json', {'writer':'B','epoch':operation['new_epoch'],'config_sha':'0'*64}):
                with self.subTest(value=value), self.m.Journal(root) as journal:
                    encoded=value if isinstance(value,str) else json.dumps(value)
                    journal.db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase='route' AND status='done'",(encoded,operation['id'])); journal.db.commit()
                    with self.assertRaises(RuntimeError): self.m.current_writer(journal,ingress)
                    self.assertFalse(self.m.ingress_allowed(root,root/'missing',root/'missing',ingress,'boot'))

    def test_completed_reconcile_refuses_every_route_authority_mutation(self):
        mutations=(
            ('wrong-writer',lambda op,digest:{'writer':'A','epoch':op['new_epoch'],'config_sha':digest}),
            ('wrong-epoch',lambda op,digest:{'writer':'B','epoch':'d1-wrong','config_sha':digest}),
            ('missing-key',lambda op,digest:{'writer':'B','epoch':op['new_epoch']}),
            ('extra-key',lambda op,digest:{'writer':'B','epoch':op['new_epoch'],'config_sha':digest,'extra':1}),
            ('stale-config-sha',lambda op,digest:{'writer':'B','epoch':op['new_epoch'],'config_sha':'0'*64}),
            ('wrong-config-sha',lambda op,digest:{'writer':'B','epoch':op['new_epoch'],'config_sha':'f'*64}),
            ('malformed-json',lambda op,digest:'{not-json'),
        )
        for name,make_value in mutations:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
                digest=hashlib.sha256(ingress.read_bytes()).hexdigest(); stopped=[]
                with self.m.Journal(root) as journal:
                    operation=journal.begin('A','B','d1-current')
                    for phase in D2:
                        evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                        journal.step(phase,lambda evidence=evidence:evidence)
                    journal.finish()
                maintenance=root/'maintenance'; maintenance.write_text(json.dumps({'operation':operation['id']})); maintenance.chmod(0o600)
                with self.m.Journal(root) as journal:
                    value=make_value(operation,digest)
                    journal.db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase='route' AND status='done'",(value if isinstance(value,str) else json.dumps(value),operation['id'])); journal.db.commit()
                    with self.assertRaises(RuntimeError): self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
                self.assertTrue(maintenance.exists()); self.assertEqual(stopped,[])

    def test_incomplete_d2_admission_accepts_only_exact_route_intent_boundary(self):
        def setup():
            root=Path(tempfile.mkdtemp()).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route A\\n')
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-current')
                for phase in D2[:8]: journal.step(phase,lambda:{})
                with self.assertRaises(RuntimeError): journal.step('route',lambda: (_ for _ in ()).throw(RuntimeError('pending')))
            maintenance=root/'maintenance'; maintenance.write_text(json.dumps({'operation':operation['id']})); maintenance.chmod(0o600)
            permit=root/'permit'; permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),'birth':self.m.process_identity(os.getpid()),'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()})); permit.chmod(0o600)
            return root,operation,ingress,maintenance,permit
        root,operation,ingress,maintenance,permit=setup()
        with mock.patch.object(self.m,'process_identity',return_value='stable-birth'):
            permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),'birth':'stable-birth','config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()}))
            self.assertTrue(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))
        import shutil
        shutil.rmtree(root)
        cases=('missing','reordered','duplicate','extra','nonempty-intent')
        for case in cases:
            with self.subTest(case=case):
                root,operation,ingress,maintenance,permit=setup()
                with self.m.Journal(root) as journal:
                    if case=='missing': journal.db.execute("DELETE FROM steps WHERE operation=? AND phase='quiesce'",(operation['id'],))
                    elif case=='reordered':
                        journal.db.execute("UPDATE steps SET phase='tmp' WHERE operation=? AND phase='preflight' AND status='intent'",(operation['id'],))
                        journal.db.execute("UPDATE steps SET phase='preflight' WHERE operation=? AND phase='close_ingress' AND status='intent'",(operation['id'],))
                        journal.db.execute("UPDATE steps SET phase='close_ingress' WHERE operation=? AND phase='tmp' AND status='intent'",(operation['id'],))
                    elif case=='duplicate': journal.db.execute("INSERT INTO steps(operation,position,phase,status,evidence) SELECT operation,99,phase,status,evidence FROM steps WHERE operation=? AND phase='route'",(operation['id'],))
                    elif case=='extra': journal.db.execute("INSERT INTO steps(operation,position,phase,status,evidence) VALUES(?,?,?,?,?)",(operation['id'],9,'verify','intent','{}'))
                    else: journal.db.execute("UPDATE steps SET evidence='{""x"":1}' WHERE operation=? AND phase='route' AND status='intent'",(operation['id'],))
                    journal.db.commit()
                self.assertFalse(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))
                shutil.rmtree(root)

    def test_incomplete_d2_admission_requires_exact_route_intent_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route A\\n')
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-current')
                for phase in D2[:8]: journal.step(phase,lambda:{})
                with self.assertRaises(RuntimeError): journal.step('route',lambda: (_ for _ in ()).throw(RuntimeError('pending')))
            maintenance=root/'maintenance'; maintenance.write_text(json.dumps({'operation':operation['id']})); maintenance.chmod(0o600)
            permit=root/'permit'; permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),'birth':self.m.process_identity(os.getpid()),'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()})); permit.chmod(0o600)
            args=(root,maintenance,permit,ingress,'boot')
            self.assertFalse(self.m.ingress_allowed(*args))
            with self.m.Journal(root) as journal:
                journal.db.execute("DELETE FROM steps WHERE operation=? AND phase='quiesce'",(operation['id'],)); journal.db.commit()
            self.assertFalse(self.m.ingress_allowed(*args))

    def test_ingress_allowed_rejects_dangling_maintenance_symlink_without_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route A\\n')
            maintenance=root/'maintenance'; maintenance.symlink_to(root/'missing-marker')
            self.assertFalse(self.m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))

    def test_ingress_allowed_rejects_maintenance_symlinks_for_completed_operation(self):
        for dangling in (True,False):
            with self.subTest(dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route B\\n')
                digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
                with self.m.Journal(root) as journal:
                    operation=journal.begin('A','B','d1-current')
                    for phase in D2:
                        evidence={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                        journal.step(phase,lambda evidence=evidence:evidence)
                    journal.finish()
                target=root/'marker.json'; target.write_text(json.dumps({'operation':operation['id']})); target.chmod(0o600)
                maintenance=root/'maintenance'; maintenance.symlink_to(root/'missing-marker' if dangling else target)
                self.assertFalse(self.m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))

    def test_ingress_allowed_rejects_maintenance_symlinks_for_incomplete_d2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); ingress=root/'proxy.cfg'; ingress.write_text('route A\\n')
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-current')
                for phase in D2[:8]: journal.step(phase,lambda:{})
                with self.assertRaises(RuntimeError): journal.step('route',lambda: (_ for _ in ()).throw(RuntimeError('pending')))
            target=root/'marker.json'; target.write_text(json.dumps({'operation':operation['id']})); target.chmod(0o600)
            maintenance=root/'maintenance'; maintenance.symlink_to(target)
            permit=root/'permit'; permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),'birth':self.m.process_identity(os.getpid()),'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()})); permit.chmod(0o600)
            self.assertFalse(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))
            maintenance.unlink(); maintenance.symlink_to(root/'missing-marker')
            self.assertFalse(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))

    def test_completed_legacy_rows_remain_exact_authority_and_target_b_reconciliation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();ingress=root/'proxy.cfg';ingress.write_text('route B\n')
            digest=hashlib.sha256(ingress.read_bytes()).hexdigest()
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-old')
                for phase in D2:
                    value={'writer':'B','epoch':operation['new_epoch'],'config_sha':digest} if phase=='route' else {}
                    journal.step(phase,lambda value=value:value)
                journal.finish()
                journal.db.execute("UPDATE operations SET restore_contract='legacy' WHERE id=?",(operation['id'],));journal.db.commit()
                self.assertEqual(self.m.current_writer(journal,ingress),{'operation':operation['id'],'writer':'B','epoch':operation['new_epoch']})
            maintenance=root/'maintenance'
            self.assertTrue(self.m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))
            self._maintenance(root,operation)
            with self.m.Journal(root) as journal:
                self.assertTrue(self.m.reconcile_existing(journal,maintenance,lambda:(_ for _ in ()).throw(AssertionError('must not stop')),ingress))
                new=journal.begin('B','A',operation['new_epoch'])
                self.assertEqual(journal.db.execute('SELECT restore_contract FROM operations WHERE id=?',(new['id'],)).fetchone(),('hat-restore-acceptance-1',))
            self.assertFalse(maintenance.exists())

    def test_unfinished_legacy_d3_refuses_serving_rejoin_and_reconciliation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();journal,operation,ingress=self._d3(root)
            maintenance=self._maintenance(root,operation);failure=root/operation['id']/'failure.json'
            journal.db.execute("UPDATE operations SET restore_contract='legacy' WHERE id=?",(operation['id'],));journal.db.commit()
            self.assertFalse(self.m._d3_serving_state(journal.db,operation['id'],hashlib.sha256(ingress.read_bytes()).hexdigest(),failure))
            journal.__exit__(None,None,None)
            self.assertFalse(self.m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))
            stopped=[]
            with self.m.Journal(root) as journal:
                with self.assertRaises(RuntimeError):journal.continue_rejoin(operation['id'])
                with self.assertRaises(RuntimeError):self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
            self.assertEqual(stopped,[True]);self.assertTrue(maintenance.exists())

    def test_unfinished_legacy_d2_refuses_ingress_and_closes_on_reconcile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();ingress=root/'proxy.cfg';ingress.write_text('route A\n');maintenance=root/'maintenance'
            with self.m.Journal(root) as journal:
                operation=journal.begin('A','B','d1-old')
                journal.step('preflight',lambda:{})
                journal.db.execute("UPDATE operations SET restore_contract='legacy' WHERE id=?",(operation['id'],));journal.db.commit()
            self._maintenance(root,operation)
            self.assertFalse(self.m.ingress_allowed(root,maintenance,root/'permit',ingress,'boot'))
            stopped=[]
            with self.m.Journal(root) as journal:
                with self.assertRaises(RuntimeError):self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
            self.assertEqual(stopped,[True]);self.assertTrue(maintenance.exists())

    def test_d3_bootstrap_requires_exact_boundary_and_live_private_permit(self):
        for boundary in ('route-intent','verify-intent'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();journal,operation,ingress=self._d3(root,count=8 if boundary=='route-intent' else 9)
                pending='route' if boundary=='route-intent' else 'verify'
                with self.assertRaises(RuntimeError):journal.step(pending,lambda:(_ for _ in ()).throw(RuntimeError('pending')))
                maintenance=self._maintenance(root,operation);permit=root/'permit'
                value={'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),
                       'birth':'live-birth','config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()}
                permit.write_text(json.dumps(value));permit.chmod(0o600);journal.__exit__(None,None,None)
                args=(root,maintenance,permit,ingress,'boot')
                identity=lambda pid:'live-birth' if pid==os.getpid() else None
                with mock.patch.object(self.m,'process_identity',side_effect=identity):
                    self.assertTrue(self.m.ingress_allowed(*args))
                    for patch in ({'boot_id':'stale'},{'birth':'stale'},{'pid':999999999},{'operation':'f'*32},{'extra':True}):
                        permit.write_text(json.dumps(dict(value,**patch)))
                        self.assertFalse(self.m.ingress_allowed(*args),patch)
                    permit.write_text(json.dumps(value));permit.chmod(0o644)
                    self.assertFalse(self.m.ingress_allowed(*args))

    def test_d3_bootstrap_rejects_early_failed_or_empty_proof_boundary(self):
        for case in ('early','route-done','failure','empty-proof'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                count=7 if case=='early' else 8 if case=='empty-proof' else 9
                root=Path(tmp).resolve();journal,operation,ingress=self._d3(root,count=count)
                if case in ('failure','empty-proof'):
                    pending='route' if case=='empty-proof' else 'verify'
                    with self.assertRaises(RuntimeError):journal.step(pending,lambda:(_ for _ in ()).throw(RuntimeError('pending')))
                if case=='empty-proof':
                    journal.db.execute("UPDATE steps SET evidence='{}' WHERE operation=? AND phase='baseline' AND status='done'",(operation['id'],));journal.db.commit()
                maintenance=self._maintenance(root,operation);permit=root/'permit'
                permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),
                    'birth':self.m.process_identity(os.getpid()),'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()}));permit.chmod(0o600)
                if case=='failure':
                    work=root/operation['id'];work.mkdir(mode=0o700)
                    failure=work/'failure.json';failure.write_text(json.dumps({'phase':'verify','error':'RuntimeError'}));failure.chmod(0o600)
                journal.__exit__(None,None,None)
                self.assertFalse(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))

    def test_d3_proof_is_required_for_continuation_and_serving(self):
        cases={
            'empty-restore':('restore',{}),
            'cut-disagreement':('compare',{'positions':{'main':10,'session':20,'aux':31},'signature':{db:hashlib.sha256(('cut-'+db).encode()).hexdigest() for db in ('main','session','aux')},'auth_and_records':'PASS'}),
            'compare-auth-failed':('compare',{'positions':{'main':10,'session':20,'aux':30},'signature':{db:hashlib.sha256(('cut-'+db).encode()).hexdigest() for db in ('main','session','aux')},'auth_and_records':'FAIL'}),
            'compare-signature-differs':('compare',{'positions':{'main':10,'session':20,'aux':30},'signature':{db:'f'*64 for db in ('main','session','aux')},'auth_and_records':'PASS'}),
            'bad-signature':('baseline',{'epoch':'REPLACE','positions':{'main':11,'session':21,'aux':31},'signature':{},'auth_and_records':'PASS'}),
            'no-baseline-auth':('baseline',{'epoch':'REPLACE','positions':{'main':11,'session':21,'aux':31},'signature':{db:hashlib.sha256(('baseline-'+db).encode()).hexdigest() for db in ('main','session','aux')},'auth_and_records':'FAIL'}),
            'wrong-baseline-epoch':('baseline',{'epoch':'d1-wrong','positions':{'main':1,'session':1,'aux':1},'signature':{db:hashlib.sha256(('baseline-'+db).encode()).hexdigest() for db in ('main','session','aux')},'auth_and_records':'PASS'}),
            'not-beyond-baseline':('verify',{'writer':'A','epoch':'REPLACE','positions':{'main':1,'session':2,'aux':2},'new_writes':{'positions':{'main':1,'session':2,'aux':2},'signature':{db:hashlib.sha256(('fresh-'+db).encode()).hexdigest() for db in ('main','session','aux')},'auth_and_records':'PASS'}}),
            'empty-new-writes':('verify',{'writer':'A','epoch':'REPLACE','positions':{'main':12,'session':22,'aux':32},'new_writes':{}}),
        }
        for name,(phase,replacement) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();journal,operation,ingress=self._d3(root)
                replacement=json.loads(json.dumps(replacement).replace('REPLACE',operation['new_epoch']))
                journal.db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase=? AND status='done'",
                                   (json.dumps(replacement),operation['id'],phase));journal.db.commit()
                maintenance=self._maintenance(root,operation);journal.__exit__(None,None,None)
                self.assertFalse(self.m.ingress_allowed(root,maintenance,root/'missing',ingress,'boot'))
                with self.m.Journal(root) as journal:
                    with self.assertRaises(RuntimeError):journal.continue_rejoin(operation['id'])

    def test_verified_d3_pause_and_failed_rejoin_keep_exact_a_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); journal,operation,ingress=self._d3(root)
            maintenance=self._maintenance(root,operation); permit=root/'missing-permit'
            journal.__exit__(None,None,None)
            args=(root,maintenance,permit,ingress,'boot')
            self.assertTrue(self.m.ingress_allowed(*args))
            stopped=[]
            with self.m.Journal(root) as journal:
                with self.assertRaises(RuntimeError): self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
                with self.assertRaises(RuntimeError): journal.begin('A','B',operation['new_epoch'])
                journal.continue_rejoin(operation['id'])
                with self.assertRaises(RuntimeError): journal.step('rejoin_boot',lambda:(_ for _ in ()).throw(RuntimeError('cold inspection failed')))
            work=root/operation['id'];work.mkdir(mode=0o700)
            failure=work/'failure.json';failure.write_text(json.dumps({'phase':'rejoin_boot','error':'RuntimeError'}));failure.chmod(0o600)
            self.assertTrue(self.m.ingress_allowed(*args))
            with self.m.Journal(root) as journal:
                with self.assertRaises(RuntimeError): self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
            self.assertEqual(stopped,[]);self.assertEqual(ingress.read_text(),'route A\n')

    def test_d3_gate_recognizes_each_post_verification_rejoin_tail_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();journal,operation,ingress=self._d3(root)
            maintenance=self._maintenance(root,operation);args=(root,maintenance,root/'permit',ingress,'boot')
            journal.__exit__(None,None,None)
            with self.m.Journal(root) as journal:
                journal.continue_rejoin(operation['id'])
                for phase in D3[10:]:
                    journal.step(phase,lambda:{})
                    self.assertTrue(self.m.ingress_allowed(*args))
                journal.finish()
            self.assertFalse(self.m.ingress_allowed(*args))
            maintenance.unlink()
            self.assertTrue(self.m.ingress_allowed(*args))

    def test_d3_gate_fails_closed_for_early_bad_evidence_or_unknown_failure(self):
        for case in ('early','wrong-writer','wrong-route','wrong-failure'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve(); count=9 if case=='early' else 10
                journal,operation,ingress=self._d3(root,count=count,verify_writer='B' if case=='wrong-writer' else 'A')
                maintenance=self._maintenance(root,operation);journal.__exit__(None,None,None)
                if case=='wrong-route':ingress.write_text('route elsewhere\n')
                if case=='wrong-failure':
                    work=root/operation['id'];work.mkdir(mode=0o700)
                    failure=work/'failure.json';failure.write_text(json.dumps({'phase':'compare','error':'RuntimeError'}));failure.chmod(0o600)
                permit=root/'permit'
                permit.write_text(json.dumps({'operation':operation['id'],'boot_id':'boot','pid':os.getpid(),
                    'birth':self.m.process_identity(os.getpid()),'config_sha':hashlib.sha256(ingress.read_bytes()).hexdigest()}));permit.chmod(0o600)
                self.assertFalse(self.m.ingress_allowed(root,maintenance,permit,ingress,'boot'))
                stopped=[]
                with self.m.Journal(root) as journal:
                    with self.assertRaises(RuntimeError):self.m.reconcile_existing(journal,maintenance,lambda:stopped.append(True),ingress)
                self.assertEqual(stopped,[True])


if __name__ == '__main__': unittest.main()
