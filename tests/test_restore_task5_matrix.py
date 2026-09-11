"""Deterministic crash-boundary matrix for unified restore acceptance (Task5)."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import control
import descriptor
import recovery
from acceptance_fixtures import acceptance_result, DBS


class JournalStub:
    def __init__(self):
        self.checks = 0
        self.pending = False
        self.next = 0
    def check_authority(self):
        self.checks += 1


class _Proc:
    returncode = 0
    def __init__(self, communication=None):
        self.killed = self.waited = False
        self.communication = communication
    def poll(self):
        return None if not self.killed else -9
    def communicate(self, input=None, timeout=None):
        if self.communication: raise self.communication
        return b'', b''
    def kill(self): self.killed = True
    def wait(self, timeout=None): self.waited = True


class RestoreTask5Matrix(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.tmp.name).resolve()
    def tearDown(self): self.tmp.cleanup()

    def io(self, real_journal=False):
        op = {'id': 'a' * 32, 'source': 'A', 'target': 'B',
              'source_epoch': 'd1-source', 'new_epoch': 'd1-' + 'a' * 32}
        if real_journal:
            return op, control.Journal(self.root)
        return op, control.ControlIO(JournalStub(), {}, op, self.root, {})

    @staticmethod
    def rows(journal):
        return journal.db.execute(
            'SELECT position,phase,status,evidence FROM steps ORDER BY rowid').fetchall()

    def _pending(self, journal, position, evidence=None):
        op = journal.begin('A', 'B', 'd1-source')
        values = [{}, {}, {}, {},
                  {'cut': {'main': 1, 'session': 1, 'aux': 1},
                   'signature': {'main': 'm', 'session': 's', 'aux': 'x'}},
                  {}, {'writer': 'B'},
                  {'request': {'positions': {'main': 1, 'session': 1, 'aux': 1}},
                   'signature': {'main': 'm', 'session': 's', 'aux': 'x'}}, {}, {}]
        for index in range(position):
            journal.step(control.PHASES[index], lambda value=values[index]: value)
        if evidence is None:
            evidence = {}
        with self.assertRaises(RuntimeError):
            journal.step(control.PHASES[position], lambda: (_ for _ in ()).throw(RuntimeError('crash')))
        return op

    def _full_operation(self, journal):
        op = journal.begin('A', 'B', 'd1-source')
        for phase in control.PHASES:
            journal.step(phase, lambda: {})
        return op

    # A: SQLite commit and migration boundaries.
    def test_journal_commit_boundaries_before_after_exact_rows_and_no_replay(self):
        cases = ('begin', 'step-intent:preflight', 'step-done:preflight',
                 'accept-comparison-done', 'accept-verification-done', 'finish')
        for label in cases:
            for when in ('before', 'after'):
                with self.subTest(label=label, when=when):
                    root = Path(tempfile.mkdtemp(dir=Path.cwd()))
                    actions = []
                    j = control.Journal(root)
                    j.__enter__()
                    hook = ('_before_commit' if when == 'before' else '_after_commit')
                    setattr(j, hook, lambda value, label=label: (_ for _ in ()).throw(
                        RuntimeError(label)) if value == label else None)
                    if label == 'begin':
                        with self.assertRaises(RuntimeError): j.begin('A', 'B', 'd1-source')
                    elif label == 'step-intent:preflight':
                        j.begin('A', 'B', 'd1-source')
                        with self.assertRaises(RuntimeError): j.step('preflight', lambda: actions.append(1))
                    elif label == 'step-done:preflight':
                        j.begin('A', 'B', 'd1-source')
                        with self.assertRaises(RuntimeError): j.step('preflight', lambda: (_ for _ in ()).throw(RuntimeError('crash')))
                        j.db.execute('DELETE FROM steps'); j.db.commit(); j.pending = False; j.next = 0
                        with self.assertRaises(RuntimeError): j.step('preflight', lambda: actions.append(1) or {})
                    elif label == 'accept-comparison-done':
                        op = self._pending(j, 5)
                        result = {'request': {'positions': {'main': 1, 'session': 1, 'aux': 1}},
                                  'signature': {'main': 'm', 'session': 's', 'aux': 'x'},
                                  'checks': {'records': 'PASS', 'authentication': 'PASS'}}
                        with self.assertRaises(RuntimeError): j.accept_comparison(op['id'], result)
                    elif label == 'accept-verification-done':
                        op = self._pending(j, 9)
                        # This is intentionally a commit seam test; validation is isolated.
                        with patch.object(recovery, 'validate_acceptance_result', return_value=None), \
                             patch.object(control, 'phase_plan', return_value=control.PHASES):
                            baseline_request = {'phase':'verification-baseline','source':'A','target':'B','profile':'baseline','epoch':op['new_epoch'],'positions': {'main':1,'session':1,'aux':1}}
                            fresh_request = {'phase':'new-writes','source':'A','target':'B','profile':'fresh-writes','epoch':op['new_epoch'],'positions': {'main':2,'session':2,'aux':2}}
                            result = {'writer': 'B', 'epoch': op['new_epoch'],
                                      'positions': {'main': 2, 'session': 2, 'aux': 2},
                                      'baseline_recheck': {'request': baseline_request, 'signature': {'main':'m','session':'s','aux':'x'}},
                                      'new_writes': {'request': fresh_request, 'signature': {'main':'m','session':'s','aux':'x'}}}
                            with self.assertRaises(RuntimeError): j.accept_verification(op['id'], result)
                    else:
                        self._full_operation(j)
                        with self.assertRaises(RuntimeError): j.finish()
                    j.__exit__(None, None, None)
                    with control.Journal(root) as reopened:
                        operation_count = reopened.db.execute('SELECT count(*) FROM operations').fetchone()[0]
                        rows = self.rows(reopened)
                        self.assertEqual(actions.count(1), 1 if label == 'step-done:preflight' else 0)
                        self.assertEqual(operation_count, 0 if label == 'begin' and when == 'before' else 1)
                        if label == 'step-intent:preflight':
                            self.assertEqual(len(rows), 0 if when == 'before' else 1)
                        elif label == 'step-done:preflight':
                            self.assertEqual(len(rows), 1 if when == 'before' else 2)
                        elif label == 'accept-comparison-done':
                            self.assertEqual(rows[-1][2], 'intent' if when == 'before' else 'done')
                        elif label == 'accept-verification-done':
                            self.assertEqual(rows[-1][2], 'intent' if when == 'before' else 'done')
                        elif label == 'finish':
                            self.assertEqual(reopened.db.execute('SELECT complete FROM operations').fetchone()[0],
                                             0 if when == 'before' else 1)
                    self.assertEqual(actions.count(1), 1 if label == 'step-done:preflight' else 0)

    def _legacy(self):
        db = sqlite3.connect(self.root / 'journal.db')
        db.executescript(control._OPERATIONS_LEGACY_SQL + ';' + control._UNFINISHED_SQL + ';' + control._STEPS_SQL + ';')
        db.close(); (self.root / 'journal.db').chmod(0o600)

    def test_migration_reopens_exact_old_or_new_at_three_boundaries(self):
        for label, expected in (('migration', 'old'), ('journal-root-fsync', 'new'), ('root-fsync', 'new')):
            with self.subTest(label=label):
                root = Path(tempfile.mkdtemp(dir=Path.cwd())); self._legacy_at(root)
                j = control.Journal(root)
                if label == 'migration':
                    j._before_commit = lambda value: (_ for _ in ()).throw(RuntimeError('alter-before-commit')) if value == label else None
                elif label == 'journal-root-fsync':
                    j._after_commit = lambda value: (_ for _ in ()).throw(RuntimeError('commit-before-root')) if value == 'migration' else None
                    j._after_root_fsync = lambda value: (_ for _ in ()).throw(RuntimeError('root-before-reopen')) if value == label else None
                else:
                    j._after_root_fsync = lambda value: (_ for _ in ()).throw(RuntimeError('root-fsync')) if value == label else None
                with self.assertRaises(RuntimeError): j.__enter__()
                db = sqlite3.connect(root / 'journal.db')
                self.assertEqual(control._journal_schema(db), control.LEGACY_RESTORE_CONTRACT if expected == 'old' else control.RESTORE_CONTRACT)
                db.close()

    def _legacy_at(self, root):
        db = sqlite3.connect(root / 'journal.db')
        db.executescript(control._OPERATIONS_LEGACY_SQL + ';' + control._UNFINISHED_SQL + ';' + control._STEPS_SQL + ';')
        db.close(); (root / 'journal.db').chmod(0o600)

    # B: all durable request/copy seams are named, and never start a command.
    def test_fsync_matrix_preserves_prior_artifacts_and_leaves_later_absent(self):
        source = self.root / 'source'; source.write_bytes(b'source'); source.chmod(0o600)
        op, io = self.io(); io.journal.pending = True; io.journal.next = 5
        digest = hashlib.sha256(b'source').hexdigest()
        def sync(label):
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: io._fsync(fd, label, self.root)
            finally: os.close(fd)
        stages = [
            ('acceptance-request.file', 'request', lambda: io._durable_bytes(self.root/'request', b'{}', label='acceptance-request')),
            ('acceptance-request.dir', 'request', lambda: sync('acceptance-request.dir')),
            ('new-writes-input-authority.file', 'authority', lambda: io._durable_bytes(self.root/'authority', b'{}', label='new-writes-input-authority')),
            ('new-writes-input-authority.dir', 'authority', lambda: sync('new-writes-input-authority.dir')),
            ('oracle-replica-config.file', 'replica', lambda: io._durable_bytes(self.root/'replica', b'replica', label='oracle-replica-config')),
            ('oracle-replica-config.dir', 'replica', lambda: sync('oracle-replica-config.dir')),
            ('oracle-ledger.file', 'ledger', lambda: io._copy_bound(source, self.root/'ledger-copy', 0o600, os.geteuid(), os.getegid(), digest, label='oracle-ledger')),
            ('oracle-ledger.dir', 'ledger', lambda: sync('oracle-ledger.dir')),
            ('oracle-fault-ledger.file', 'fault', lambda: io._copy_bound(source, self.root/'fault-copy', 0o600, os.geteuid(), os.getegid(), digest, label='oracle-fault-ledger')),
            ('oracle-fault-ledger.dir', 'fault', lambda: sync('oracle-fault-ledger.dir')),
            ('oracle-request.file', 'oracle-request', lambda: io._copy_bound(source, self.root/'oracle-request', 0o600, os.geteuid(), os.getegid(), digest, label='oracle-request')),
            ('oracle-request.dir', 'oracle-request', lambda: sync('oracle-request.dir')),
            ('oracle-area.file', 'area', lambda: io._durable_bytes(self.root/'area-result', b'result', label='oracle-area')),
            ('oracle-area.dir', 'area', lambda: sync('oracle-area.dir')),
        ]
        for fail, current, _ in stages:
            with self.subTest(fail=fail):
                for path in tuple(self.root.iterdir()):
                    if path.name != 'source' and path.is_file(): path.unlink()
                seen = []; spawn = Mock(); io.command = spawn
                io._before_fsync = lambda label, path: seen.append(label)
                io._after_fsync = lambda label, path, fail=fail: (_ for _ in ()).throw(RuntimeError(fail)) if label == fail else None
                with self.assertRaises((RuntimeError, FileExistsError)):
                    for stage_label, _, action in stages:
                        action()
                self.assertEqual(seen[-1], fail); spawn.assert_not_called()
                failed_index = next(i for i, item in enumerate(stages) if item[0] == fail)
                paths = {'request':'request','authority':'authority','replica':'replica','ledger':'ledger-copy','fault':'fault-copy','oracle-request':'oracle-request','area':'area-result'}
                first = {artifact: next(i for i, item in enumerate(stages) if item[1] == artifact) for artifact in paths}
                for artifact, filename in paths.items():
                    if first[artifact] <= failed_index: self.assertTrue((self.root / filename).exists())
                    else: self.assertFalse((self.root / filename).exists())
                self.assertTrue(io.journal.pending); self.assertFalse(any(row[2] == 'done' for row in getattr(io.journal, 'rows', [])))

    def test_protected_authority_and_fresh_authority_use_real_control_io(self):
        op, io = self.io(); ledger = self.root/'ledger.jsonl'; ledger.write_bytes(b'ledger\n'); ledger.chmod(0o600)
        support = {name: 'b'*64 for name in ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')}
        binaries = {'trail':'c'*64, 'litestream':'d'*64}
        with patch.object(recovery, '_authority'):
            authority = io.capture_protected_authority(ledger, 'd2-preflight', support, binaries)
        self.assertEqual(authority['ledger']['inode'], ledger.stat().st_ino)
        fresh = self.root/'new-writes.jsonl'; fresh.write_bytes(b'fresh\n'); fresh.chmod(0o600)
        io.state = {'A': {'config': {'support': support, 'binaries': binaries}}}
        io.journal.pending = True; io.journal.next = 9
        with patch.object(recovery, '_authority'):
            actual = io.authorize_fresh_writes(fresh)
        self.assertEqual(actual['origin'], 'current-verify-exclusive')
        self.assertEqual(json.loads((self.root/'new-writes-input-authority.json').read_text()), actual)

    # C: subprocess uncertainty and cleanup.
    def test_command_boundaries_retain_intent_output_and_uncertainty(self):
        for boundary in ('pre-spawn', 'start-oserror', 'post-start', 'communication', 'timeout'):
            with self.subTest(boundary=boundary):
                for old in self.root.iterdir():
                    if old.is_file(): old.unlink()
                op, io = self.io(); calls = []
                if boundary == 'pre-spawn': io._before_command_spawn = lambda argv: (_ for _ in ()).throw(RuntimeError('pre'))
                process = _Proc(subprocess.TimeoutExpired(['fake'], 0)) if boundary == 'timeout' else _Proc(OSError('communicate')) if boundary == 'communication' else _Proc()
                popen = Mock(side_effect=OSError('start') if boundary == 'start-oserror' else None,
                              return_value=process)
                if boundary == 'post-start': io._after_command_start = lambda child: (_ for _ in ()).throw(RuntimeError('post'))
                with patch.object(control.subprocess, 'Popen', popen):
                    with self.assertRaises((RuntimeError, OSError, subprocess.TimeoutExpired)):
                        io.command(['fake'], data=b'intent')
                self.assertEqual(popen.call_count, 0 if boundary == 'pre-spawn' else 1)
                self.assertEqual(len(list(self.root.glob('*.intent.json'))), 1)
                if boundary == 'pre-spawn':
                    self.assertEqual(list(self.root.glob('*.outcome.json')), [])
                else:
                    outcome = json.loads(next(self.root.glob('*.outcome.json')).read_text())
                    self.assertEqual(outcome['uncertain'], boundary not in ('start-oserror',))
                    self.assertTrue(list(self.root.glob('*.stdout')) and list(self.root.glob('*.stderr')))
                if boundary in ('post-start', 'communication', 'timeout'):
                    self.assertTrue(process.killed); self.assertTrue(process.waited)

    def test_command_uncertain_pending_reopens_without_second_oracle_spawn(self):
        root = Path(tempfile.mkdtemp(dir=Path.cwd())); j = control.Journal(root)
        io = control.ControlIO(j, {}, {}, root, {})
        j.__enter__(); op = j.begin('A','B','d1-source')
        with self.assertRaises(RuntimeError): j.step('preflight', lambda: (_ for _ in ()).throw(RuntimeError('crash')))
        j.__exit__(None,None,None)
        with control.Journal(root) as reopened:
            self.assertEqual(self.rows(reopened)[0][2], 'intent')
            self.assertIsNone(reopened.operation)
            with self.assertRaises(RuntimeError): reopened.begin('A','B','d1-source')

    # D: result read/replacement/retention and a fake oracle command.
    def test_result_read_and_retained_fsync_boundaries_preserve_artifacts(self):
        op, io = self.io(); result = self.root/'result.json'; result.write_bytes(b'{"ok":true}'); result.chmod(0o600)
        authority = descriptor.DescriptorAuthority.open_file(result, trusted_root=self.root, trusted_uids={os.geteuid()}, expected_mode=0o600)
        try:
            seen = []
            io._before_result_read = lambda path: seen.append('before')
            io._after_result_read = lambda path: seen.append('after')
            self.assertEqual(io._read_result(authority, result), b'{"ok":true}')
            self.assertEqual(seen, ['before','after'])
            result.rename(self.root/'old'); result.write_bytes(b'{"ok":true}'); result.chmod(0o600)
            with self.assertRaises(ValueError): io._recheck_result(authority, result)
        finally: authority.close()
        source = self.root/'source'; source.write_bytes(b'retained'); source.chmod(0o600)
        for label in ('retained-result.file','retained-result.dir'):
            destination = self.root/('retained-' + label[-4:])
            io._before_fsync = lambda value, path: None
            io._after_fsync = lambda value, path, label=label: (_ for _ in ()).throw(RuntimeError(label)) if value == label else None
            with self.assertRaises(RuntimeError): io._copy_bound(source, destination, 0o600, os.geteuid(), os.getegid(), hashlib.sha256(b'retained').hexdigest(), label='retained-result')
            self.assertEqual(source.read_bytes(), b'retained'); self.assertTrue(destination.exists())

    def test_oracle_fake_command_creates_canonical_result_before_controller_read(self):
        op, io = self.io(); positions = {'main':1,'session':1,'aux':1}
        ledger = self.root/'ledger.jsonl'; ledger.write_bytes(b'ledger\n'); ledger.chmod(0o600)
        base = acceptance_result(op, 'compare', positions)
        request = base['request']; request['inputs']['ledger_authority']['ledger'].update(
            path=str(ledger), device=ledger.stat().st_dev, inode=ledger.stat().st_ino,
            bytes=ledger.stat().st_size, uid=os.geteuid())
        request['inputs']['ledger_authority']['ledger']['sha256'] = hashlib.sha256(ledger.read_bytes()).hexdigest()
        request['inputs']['ledger_sha256'] = request['inputs']['ledger_authority']['ledger']['sha256']
        request['inputs']['replica_config_sha256'] = hashlib.sha256(b'config').hexdigest()
        request_bytes = recovery.canonical_json(request)
        base['request_sha256'] = hashlib.sha256(request_bytes).hexdigest(); result_bytes = recovery.canonical_json(base)
        class Authority:
            identity = (ledger.stat().st_dev, ledger.stat().st_ino, ledger.stat().st_mode, os.geteuid(), os.getegid(), 1, ledger.stat().st_size)
            sha256 = request['inputs']['ledger_sha256']
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return ledger.read_bytes()
            def recheck(self): return self
        io._acceptance_request = Mock(return_value=(request, request_bytes, [], Authority.identity))
        io._installed_manifest = Mock(side_effect=[request['inputs']['support'], request['inputs']['binaries']])
        def fake_copy(source, destination, *args, **kwargs): Path(destination).write_bytes(Path(source).read_bytes()); return None
        def fake_command(argv, data=None, timeout=180):
            result_path = Path(argv[argv.index('--result') + 1]); result_path.write_bytes(result_bytes); result_path.chmod(0o600); return b''
        def open_file(path, **kwargs):
            if Path(path).name == 'result.json':
                auth = Authority(); auth.read = lambda: result_bytes; auth.sha256 = hashlib.sha256(result_bytes).hexdigest(); return auth
            return Authority()
        oracle_base = self.root/'oracle-root'; oracle_base.mkdir(mode=0o700)
        original_path = control.Path
        def redirected(value, *args): return oracle_base if value == '/var/lib/hat-oracle' else original_path(value, *args)
        with patch.object(control, 'Path', side_effect=redirected), patch.object(control.pwd, 'getpwnam', return_value=type('A', (), {'pw_uid':os.geteuid(),'pw_gid':os.getegid()})()), patch.object(control.os, 'chown'), patch.object(control.os, 'fchown'), patch.object(control.descriptor.DescriptorAuthority, 'open_file', side_effect=open_file), patch.object(control, '_open_held_inputs', return_value=[]), patch.object(io, '_reopen_exact_bytes'), patch.object(io, '_recheck_installed_manifest'), patch.object(io, '_copy_bound', side_effect=fake_copy), patch.object(io, 'command', side_effect=fake_command), patch.object(recovery, '_protected_ledger'), patch.object(recovery, 'parse_acceptance_result', return_value=base):
            value = io.oracle('compare', 'config', positions, ledger)
        self.assertEqual(value['request'], request); self.assertTrue((self.root/'compare-acceptance-result.json').exists())

    # E: every partial artifact is pending, never accepted on reopen.
    def test_partial_reopen_matrix_refuses_all_artifacts_and_no_action(self):
        names = ('authority.json','compare-acceptance-request.json','oracle-replica.yml',
                 'oracle-ledger.jsonl','command.outcome.json','result.json','compare-acceptance-result.json')
        for name in names:
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp(dir=Path.cwd())); j = control.Journal(root); j.__enter__()
                op = j.begin('A','B','d1-source')
                with self.assertRaises(RuntimeError): j.step('preflight', lambda: (_ for _ in ()).throw(RuntimeError('intent')))
                work = root/op['id']; work.mkdir(mode=0o700); (work/name).write_bytes(b'partial'); j.__exit__(None,None,None)
                ingress = root/'ingress'; ingress.write_bytes(b'route'); ingress.chmod(0o600)
                with control.Journal(root) as fresh:
                    self.assertEqual(self.rows(fresh), [(0,'preflight','intent','{}')])
                    with self.assertRaises(RuntimeError): control.current_writer(fresh, ingress)
                    self.assertFalse(control.ingress_allowed(root, root/'maintenance', root/'permit', ingress, 'boot'))

    # F: inode and same-size/hash replacements are refused for every artifact class.
    def test_replacement_matrix_same_path_inode_and_content_changes_refuse(self):
        for name in ('ledger.jsonl','request.json','config.yml','fault.jsonl','result.json','retained.json'):
            for mutation in ('inode','content'):
                with self.subTest(name=name, mutation=mutation):
                    path = self.root/name; path.write_bytes(b'fixed'); path.chmod(0o600)
                    authority = descriptor.DescriptorAuthority.open_file(path, trusted_root=self.root, trusted_uids={os.geteuid()}, expected_mode=0o600)
                    try:
                        if mutation == 'inode': path.rename(self.root/'old'); path.write_bytes(b'fixed'); path.chmod(0o600)
                        else: path.write_bytes(b'other')
                        with self.assertRaises(ValueError): authority.recheck()
                    finally: authority.close()
        for name in ('source-parent', 'retained-parent'):
            parent = self.root/name; parent.mkdir(mode=0o700)
            auth = descriptor.DescriptorAuthority.open_directory(parent, trusted_root=self.root, trusted_uids={os.geteuid()})
            parent.rename(self.root/(name + '-old')); parent.mkdir(mode=0o700)
            try:
                with self.assertRaises(ValueError): auth.recheck()
            finally: auth.close()

    def test_completed_authority_negative_matrix_only_exact_route_done_is_accepted(self):
        cases = {
            'route-digest': lambda route: route.update(config_sha='0' * 64),
            'route-epoch': lambda route: route.update(epoch='d1-' + 'b' * 32),
            'route-writer': lambda route: route.update(writer='A'),
            'route-intent': 'intent', 'route-missing': 'missing',
            'non-route-done': 'non-route', 'operation-incomplete': 'incomplete',
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp(dir=Path.cwd())); j = control.Journal(root); j.__enter__()
                op = j.begin('A', 'B', 'd1-source'); ingress = root/'ingress'; ingress.write_bytes(b'route'); ingress.chmod(0o600)
                digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
                for phase in control.PHASES:
                    value = {'writer':'B','epoch':op['new_epoch'],'config_sha':digest} if phase == 'route' else {}
                    j.step(phase, lambda value=value: value)
                if mutation == 'missing':
                    j.db.execute("DELETE FROM steps WHERE phase='route'")
                elif mutation == 'non-route':
                    j.db.execute("UPDATE steps SET phase='other' WHERE phase='route'")
                elif mutation == 'incomplete':
                    j.db.execute('UPDATE operations SET complete=0 WHERE id=?', (op['id'],))
                elif mutation == 'intent':
                    j.db.execute("UPDATE steps SET status='intent' WHERE phase='route'")
                elif callable(mutation):
                    row = j.db.execute("SELECT evidence FROM steps WHERE phase='route' AND status='done'").fetchone()
                    route = json.loads(row[0]); mutation(route)
                    j.db.execute("UPDATE steps SET evidence=? WHERE phase='route' AND status='done'", (json.dumps(route),))
                j.db.commit()
                with self.assertRaises(RuntimeError): control.current_writer(j, ingress)
                self.assertFalse(control.ingress_allowed(root, root/'maintenance', root/'permit', ingress, 'boot'))
                j.__exit__(None, None, None)

        root = Path(tempfile.mkdtemp(dir=Path.cwd())); j = control.Journal(root); j.__enter__()
        op = j.begin('A', 'B', 'd1-source'); ingress = root/'ingress'; ingress.write_bytes(b'route'); ingress.chmod(0o600)
        digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
        for phase in control.PHASES:
            value = {'writer':'B','epoch':op['new_epoch'],'config_sha':digest} if phase == 'route' else {}
            j.step(phase, lambda value=value: value)
        j.finish()
        self.assertEqual(control.current_writer(j, ingress), {'operation':op['id'], 'writer':'B', 'epoch':op['new_epoch']})
        j.__exit__(None, None, None)


    def test_replacement_is_refused_by_real_writer_and_ingress_consumers(self):
        root = Path(tempfile.mkdtemp(dir=Path.cwd())); j = control.Journal(root); j.__enter__()
        op = j.begin('A', 'B', 'd1-source'); ingress = root/'ingress'; ingress.write_bytes(b'route'); ingress.chmod(0o600)
        digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
        for phase in control.PHASES:
            value = {'writer':'B','epoch':op['new_epoch'],'config_sha':digest} if phase == 'route' else {}
            j.step(phase, lambda value=value: value)
        j.finish()
        ingress.rename(root/'ingress.old'); ingress.write_bytes(b'route'); ingress.chmod(0o600)
        with self.assertRaises(RuntimeError): control.current_writer(j, ingress)
        self.assertFalse(control.ingress_allowed(root, root/'maintenance', root/'permit', ingress, 'boot'))
        j.__exit__(None, None, None)


if __name__ == '__main__': unittest.main()
