"""Local D3 recovery driver checks; all operational I/O is a fake."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control
import recovery
from tests.acceptance_fixtures import acceptance_result


DBS = ('main', 'session', 'aux')


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def replica(epoch):
    return ''.join('  path: demos/' + epoch + '/' + db + '\n' for db in DBS)


class FakeIO:
    calls = []
    scenario = None
    source = None
    candidate_epoch = None
    candidate_boot = None
    candidate_replica = None
    fault_path = None

    def __init__(self, journal, config, operation, work, state, maintenance, ingress):
        self.journal, self.operation, self.work = journal, operation, Path(work)
        self.state, self.maintenance, self.ingress = state, Path(maintenance), Path(ingress)

    @classmethod
    def record(cls, *value):
        cls.calls.append(value)

    def producer_stopped(self, unit, cgroup):
        self.record('producer-stopped', unit)
        if self.scenario == 'live-producer' and sum(c[0] == 'producer-stopped' for c in self.calls) == 1:
            raise RuntimeError('producer remains live')
        return {'unit': unit, 'load_state': 'loaded', 'main_pid': 0,
                'active_state': 'inactive', 'sub_state': 'dead', 'cgroup': 'absent'}

    def remote(self, label, action, payload=None):
        wire_action, source = control.ControlIO._REMOTE_ACTIONS[action]
        epoch = (self.state.get(label, {}).get('epoch', self.operation['source_epoch'])
                 if source == 'current' else self.operation[source])
        action = wire_action
        self.record('remote', label, action, epoch, payload)
        operation = self.operation['id']
        if action == 'inspect-cold':
            if epoch == self.candidate_epoch:
                config = dict(self.source, hostname='candidate-a', role='writer', epoch=epoch)
                text = self.candidate_replica
            else:
                config = dict(self.source, hostname='candidate-a', role='standby', epoch=epoch)
                text = replica(epoch)
            return {'operation': operation, 'epoch': epoch, 'boot_id': self.candidate_boot,
                    'authority': 'absent', 'services': {'node_service': 'static'},
                    'cgroup': 'empty', 'mutators': 'none', 'config': config,
                    'replica_config': text}
        if action == 'prepare-recovery':
            return {'operation': operation, 'original_epoch': self.candidate_epoch,
                    'original_boot_id': self.candidate_boot, 'epoch': self.operation['source_epoch'],
                    'role': 'standby'}
        if action == 'restore-recovery':
            return {'operation': operation, 'original_epoch': self.candidate_epoch,
                    'original_boot_id': self.candidate_boot, 'epoch': self.operation['source_epoch'],
                    'source_epoch': self.operation['source_epoch'], 'cut': dict(main=10, session=11, aux=12),
                    'signature': {db: hashlib.sha256(('cut-' + db).encode()).hexdigest() for db in DBS},
                    'fence_digest': payload['fence_digest']}
        if action == 'prepare':
            return {'epoch': payload['new_epoch'], 'signature': payload['signature'],
                    'fence_digest': payload['fence_digest']}
        if action == 'activate':
            return {'epoch': epoch, 'healthy': True}
        if action == 'probe':
            probes = sum(c[:3] == ('remote', 'A', 'probe') for c in self.calls)
            positions = dict(main=1, session=2, aux=3) if probes == 1 else dict(main=2, session=3, aux=4)
            config = dict(self.source, hostname='candidate-a', role='writer', epoch=epoch)
            return {'boot_id': self.candidate_boot, 'config': config,
                    'replica_config': replica(epoch),
                    'status': {'epoch': epoch, 'healthy': True, 'trailbase_running': True,
                               'positions': positions}}
        raise AssertionError(action)

    def close_ingress(self):
        self.record('close-ingress')
        self.state['ingress_touched'] = True
        if not self.maintenance.exists(): private_json(self.maintenance, {'operation': self.operation['id']})
        return {'closed': True}

    def fence(self, action, expected, label='A'):
        self.record('fence', label, action, expected)
        if self.scenario == 'running-source': raise RuntimeError('source is running')
        return {'label': label, 'action': action, 'state': expected,
                'sequence': sum(c[0] == 'fence' for c in self.calls)}

    def select_cut(self, source_replica, minimum):
        self.record('select-cut', dict(minimum))
        return {'positions': dict(main=10, session=11, aux=12), 'plans': {db: {} for db in DBS}}

    def oracle(self, phase, replica_config, positions, selected_ledger,
               fault_ledger=None):
        self.record('oracle', phase, dict(positions), fault_ledger is not None)
        if phase == 'compare' and self.scenario == 'changed-ledger':
            with self.fault_path.open('a') as stream: stream.write('{}\n')
        signature = ({db: hashlib.sha256(('cut-' + db).encode()).hexdigest() for db in DBS}
                     if phase == 'compare' else
                     {db: hashlib.sha256((phase + '-' + db).encode()).hexdigest() for db in DBS})
        if phase == 'compare' and self.scenario == 'signature-mismatch': signature['main'] = 'f' * 64
        value = acceptance_result(self.operation, phase, positions, signature)
        if phase == 'compare' and self.scenario == 'auth-fail':
            value['checks']['authentication'] = 'FAIL'
        if phase == 'compare' and self.scenario == 'lost-ack':
            value['checks']['fault_outcomes']['lost'] = value['checks']['fault_outcomes'].pop('recovered')
            value['checks']['fault_outcomes']['recovered'] = []
        return value

    def command(self, argv, data=None, timeout=180):
        self.record('command', tuple(argv))
        return b''

    def start_ingress(self, digest):
        self.record('start-ingress', digest)

    def verify_url(self, ledger):
        self.record('verify-url', str(ledger))

    def smoke_url(self, credentials, ledger):
        self.record('smoke-url', str(ledger))
        Path(ledger).write_text('{}\n'); Path(ledger).chmod(0o600)


class RecoverDriverTests(unittest.TestCase):
    def fixture(self, scenario=None):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        base = Path(temporary.name).resolve()
        root = base / 'controller'; root.mkdir(mode=0o700)
        ingress = base / 'haproxy.cfg'
        ingress.write_text('backend writer\n    server b 127.0.0.1:14003 check\n\n'
                           'backend home\n    server b 127.0.0.1:14002 check\n')
        with control.Journal(root) as journal:
            authority = journal.begin('A', 'B', 'd1-original')
            digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
            for phase in control.PHASES:
                if phase == 'preflight':
                    value = {'source_boot': 'boot-original-a', 'candidate_boot': 'boot-b'}
                elif phase == 'route':
                    value = {'writer': 'B', 'epoch': authority['new_epoch'], 'config_sha': digest}
                else:
                    value = {}
                journal.step(phase, lambda value=value: value)
            journal.finish()
        source_epoch = authority['new_epoch']; candidate_epoch = 'd1-candidate-old'
        support_dir = base / 'support'; support_dir.mkdir()
        support = {}
        for name in ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                     'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                     'secrets/keys/public_key.pem'):
            path = support_dir / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode()); support[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        binary_dir = base / 'bin'; binary_dir.mkdir()
        binaries = {}
        for name in ('trail', 'litestream'):
            path = binary_dir / name; path.write_bytes(name.encode())
            binaries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        source = {'role': 'writer', 'epoch': source_epoch, 'hostname': 'source-b',
                  'bootstrap': False, 'binaries': binaries, 'support': support}
        protected = root / 'protected.jsonl'
        protected_rows = [
            {'auth_token': 'token', 'retained_refresh': 'keep', 'revoked_refresh': 'gone'},
            {'event': 'acknowledged', 'api': 'main_ops',
             'row': {'op_key': 'd1-main', 'payload': 'old'}, 'id': '1', 'time_ns': 1},
            {'event': 'acknowledged', 'api': 'aux_ops',
             'row': {'op_key': 'd1-aux', 'payload': 'old'}, 'id': '1', 'time_ns': 2},
        ]
        protected.write_text(''.join(json.dumps(row) + '\n' for row in protected_rows))
        protected.chmod(0o600)
        baseline = root / 'protected-baseline.json'
        private_json(baseline, acceptance_result(
            authority, 'baseline', dict(main=5, session=6, aux=7),
            {db: hashlib.sha256(('protected-' + db).encode()).hexdigest() for db in DBS}))
        fault = root / 'fault.jsonl'
        rows = [
            {'event': 'start', 'run_id': 'd3-' + '1' * 32, 'source_epoch': source_epoch,
             'time_ns': 1, 'utc': '2026-09-08T00:00:00Z'},
            {'event': 'submitted', 'api': 'main_ops', 'row': {'op_key': 'd3-fault', 'payload': 'value'}, 'time_ns': 2},
            {'event': 'acknowledged', 'api': 'main_ops', 'row': {'op_key': 'd3-fault', 'payload': 'value'}, 'id': '1', 'time_ns': 3},
            {'event': 'stop', 'submitted': 1, 'acknowledged': 1, 'rejected': 0, 'uncertain': 0,
             'time_ns': 4, 'utc': '2026-09-08T00:00:01Z'},
        ]
        fault.write_text(''.join(json.dumps(row) + '\n' for row in rows)); fault.chmod(0o600)
        credentials = base / 'credentials.json'; private_json(credentials, {'email': 'x', 'password': 'y'})
        run = '2' * 32; input_path = base / 'recovery-input.json'
        value = {'authority_operation': authority['id'], 'source_epoch': source_epoch, 'source_boot': 'boot-b',
                 'source_config': source, 'source_replica': replica(source_epoch),
                 'source_health': {'authority_operation': authority['id'], 'observed_ns': 0,
                     'probe': {'boot_id': 'boot-b', 'config': source, 'replica_config': replica(source_epoch),
                               'status': {'epoch': source_epoch, 'healthy': True, 'trailbase_running': True,
                                          'positions': dict(main=5, session=6, aux=7)}}},
                 'candidate_epoch': candidate_epoch, 'candidate_boot': 'boot-a',
                 'protected_ledger': str(protected), 'protected_baseline': str(baseline),
                 'fault_ledger': str(fault), 'producer_unit': 'hat-d3-client-' + run + '.service',
                 'producer_cgroup': '/sys/fs/cgroup/system.slice/hat-d3-client-' + run + '.service'}
        private_json(input_path, value)
        maintenance = base / 'maintenance'
        FakeIO.calls, FakeIO.scenario = [], scenario
        FakeIO.source, FakeIO.candidate_epoch = source, candidate_epoch
        FakeIO.candidate_boot, FakeIO.candidate_replica = 'boot-a', replica(candidate_epoch)
        FakeIO.fault_path = fault
        args = dict(control_module=control, io_factory=FakeIO, root=root, input_path=input_path,
                    maintenance=maintenance, ingress=ingress, credentials=credentials,
                    oracle_support=support_dir, oracle_binaries=binary_dir)
        return temporary, root, authority, args

    def test_pre_fault_health_is_required_and_bound_before_producer(self):
        for case in ('missing', 'unhealthy', 'not-writer', 'boot', 'authority', 'late', 'behind'):
            with self.subTest(case=case):
                temporary, root, authority, args = self.fixture()
                self.addCleanup(temporary.cleanup)
                value = json.loads(args['input_path'].read_text())
                health = value['source_health']
                if case == 'missing': value.pop('source_health')
                elif case == 'unhealthy': health['probe']['status']['healthy'] = False
                elif case == 'not-writer': health['probe']['status']['trailbase_running'] = False
                elif case == 'boot': health['probe']['boot_id'] = 'another-boot'
                elif case == 'authority': health['authority_operation'] = 'f' * 32
                elif case == 'late': health['observed_ns'] = 2
                elif case == 'behind': health['probe']['status']['positions']['main'] = 4
                private_json(args['input_path'], value)
                with self.assertRaises((ValueError, RuntimeError)):
                    recovery.recover({'hostname': socket.gethostname()}, **args)
                self.assertEqual(FakeIO.calls, [])
                with control.Journal(root) as journal:
                    self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0], 1)

    def test_fixed_action_order_epoch_bindings_verified_pause_and_no_replay(self):
        temporary, root, authority, args = self.fixture()
        self.addCleanup(temporary.cleanup)
        operation = recovery.recover({'hostname': socket.gethostname()}, **args)
        self.assertNotEqual('boot-original-a', 'boot-b')
        with control.Journal(root) as journal:
            d2_preflight = json.loads(journal.db.execute(
                "SELECT evidence FROM steps WHERE operation=? AND phase='preflight' AND status='done'",
                (authority['id'],)).fetchone()[0])
        self.assertEqual(d2_preflight['candidate_boot'], 'boot-b')
        self.assertNotEqual(d2_preflight['source_boot'], 'boot-b')
        names = [call[0] for call in FakeIO.calls]
        self.assertEqual(names, ['producer-stopped', 'remote', 'close-ingress', 'fence', 'select-cut',
                                 'remote', 'remote', 'oracle', 'producer-stopped', 'fence', 'remote',
                                 'remote', 'remote', 'remote', 'oracle', 'command', 'start-ingress',
                                 'verify-url', 'smoke-url', 'remote', 'oracle'])
        self.assertFalse(any(call[0] == 'fence' and call[3] != 'offline' for call in FakeIO.calls))
        remote = [call for call in FakeIO.calls if call[0] == 'remote']
        self.assertEqual([(call[2], call[3]) for call in remote[:4]],
                         [('inspect-cold', 'd1-candidate-old'), ('prepare-recovery', 'd1-candidate-old'),
                          ('restore-recovery', authority['new_epoch']), ('inspect-cold', authority['new_epoch'])])
        with control.Journal(root) as journal:
            row = journal.db.execute('SELECT complete,new_epoch FROM operations WHERE id=?', (operation,)).fetchone()
            self.assertEqual(row[0], 0)
            steps = journal.db.execute('SELECT phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',
                                       (operation,)).fetchall()
            self.assertEqual([(p, s) for p, s, _ in steps],
                             [(p, s) for p in control.D3_PHASES[:10] for s in ('intent', 'done')])
            baseline = json.loads(next(e for p, s, e in steps if p == 'baseline' and s == 'done'))
            restored = json.loads(next(e for p, s, e in steps if p == 'restore' and s == 'done'))
            self.assertEqual(baseline['request']['epoch'], row[1])
            self.assertEqual(restored['cut'], {'main': 10, 'session': 11, 'aux': 12})
        with self.assertRaises(RuntimeError): recovery.recover({'hostname': socket.gethostname()}, **args)

    def test_running_source_and_live_producer_refuse_without_activation(self):
        for scenario in ('running-source', 'live-producer'):
            with self.subTest(scenario=scenario):
                temporary, root, _, args = self.fixture(scenario); self.addCleanup(temporary.cleanup)
                with self.assertRaises(RuntimeError): recovery.recover({'hostname': socket.gethostname()}, **args)
                self.assertFalse(any(call[:3] == ('remote', 'A', 'prepare') for call in FakeIO.calls))
                self.assertFalse(any(call[:3] == ('remote', 'A', 'activate') for call in FakeIO.calls))
                with control.Journal(root) as journal:
                    unfinished = journal.db.execute('SELECT count(*) FROM operations WHERE complete=0').fetchone()[0]
                    self.assertEqual(unfinished, 0 if scenario == 'live-producer' else 1)

    def test_comparison_auth_signature_and_sealed_ledger_gate_activation(self):
        for scenario in ('auth-fail', 'signature-mismatch', 'changed-ledger'):
            with self.subTest(scenario=scenario):
                temporary, root, _, args = self.fixture(scenario); self.addCleanup(temporary.cleanup)
                with self.assertRaises((RuntimeError, ValueError)): recovery.recover({'hostname': socket.gethostname()}, **args)
                self.assertFalse(any(call[:3] == ('remote', 'A', 'prepare') for call in FakeIO.calls))
                self.assertFalse(any(call[:3] == ('remote', 'A', 'activate') for call in FakeIO.calls))
                with control.Journal(root) as journal:
                    operation = journal.db.execute('SELECT id FROM operations WHERE complete=0').fetchone()[0]
                    failure = root / operation / 'failure.json'
                    self.assertTrue(failure.is_file())
                    self.assertIn(json.loads(failure.read_text())['phase'], ('compare', 'activate'))
                self.assertEqual(FakeIO.calls[-1][0], 'close-ingress')

    def test_lost_ack_refuses_comparison_preserves_intent_and_blocks_replay(self):
        temporary, root, _, args = self.fixture('lost-ack')
        self.addCleanup(temporary.cleanup)
        ingress_before = args['ingress'].read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'acknowledged writes are missing'):
            recovery.recover({'hostname': socket.gethostname()}, **args)
        self.assertFalse(any(call[0] in ('start-ingress', 'verify-url', 'smoke-url')
                             for call in FakeIO.calls))
        self.assertFalse(any(call[:3] in (('remote', 'A', 'prepare'), ('remote', 'A', 'activate'))
                             for call in FakeIO.calls))
        self.assertEqual(args['ingress'].read_bytes(), ingress_before)
        self.assertTrue(args['maintenance'].is_file())
        self.assertEqual(FakeIO.calls[-1][0], 'close-ingress')
        with control.Journal(root) as journal:
            operation = journal.db.execute('SELECT id FROM operations WHERE complete=0').fetchone()[0]
            steps = journal.db.execute('SELECT phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',
                                       (operation,)).fetchall()
            self.assertEqual([(phase, status) for phase, status, _ in steps],
                             [(p, s) for p in control.D3_PHASES[:5] for s in ('intent', 'done')]
                             + [('compare', 'intent')])
            count = journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]
        failure = root / operation / 'failure.json'
        failure_before = failure.read_bytes()
        self.assertEqual(json.loads(failure_before)['phase'], 'compare')
        calls_before = list(FakeIO.calls)
        with self.assertRaises(RuntimeError):
            recovery.recover({'hostname': socket.gethostname()}, **args)
        self.assertEqual(FakeIO.calls, calls_before)
        self.assertEqual(failure.read_bytes(), failure_before)
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT count(*) FROM operations').fetchone()[0], count)
            self.assertEqual(journal.db.execute(
                'SELECT phase,status,evidence FROM steps WHERE operation=? ORDER BY rowid',
                (operation,)).fetchall(), steps)

    def test_protected_baseline_auth_refuses_before_new_operation(self):
        temporary, root, _, args = self.fixture(); self.addCleanup(temporary.cleanup)
        contract = json.loads(Path(args['input_path']).read_text())
        report = json.loads(Path(contract['protected_baseline']).read_text())
        private_json(Path(contract['protected_baseline']), report | {'auth_and_records': 'FAIL'})
        with self.assertRaises(ValueError): recovery.recover({'hostname': socket.gethostname()}, **args)
        self.assertEqual(FakeIO.calls, [])
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT count(*) FROM operations WHERE complete=0').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
