"""Local-only native D3 rejoin checks; all provider, socket, and SSH I/O is fake."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control
import recovery

DBS = ('main', 'session', 'aux')
SOURCE_BOOT = '11111111-1111-4111-8111-111111111111'
A_BOOT = '22222222-2222-4222-8222-222222222222'
B_BOOT = '33333333-3333-4333-8333-333333333333'
CONFIG_SHA = hashlib.sha256(b'old B config bytes').hexdigest()
REPLICA_SHA = hashlib.sha256(b'old B replica bytes').hexdigest()


def cut(value):
    return {name: value + offset for offset, name in enumerate(DBS)}


def signature(prefix):
    return {name: hashlib.sha256((prefix + name).encode()).hexdigest() for name in DBS}


class FakeIO:
    scenario = None
    calls = []
    b_probes = []
    new_epoch = None

    def __init__(self, journal, config, operation, work, state, maintenance, ingress):
        self.operation = operation
        self.state = state

    def fence(self, action, expected, label='A'):
        self.calls.append(('fence', label, action, expected))
        if self.scenario == 'power-failure':
            raise RuntimeError('provider refused power-on')
        # Native provider receipts attest only provider identity/state, never guest boot.
        return {'action': action, 'state': expected, 'provider_label': 'fm2', 'instance_id': 2}

    def wait_reachable(self, label, timeout=90):
        self.calls.append(('wait-reachable', label, timeout))
        return {'label': label, 'address': '192.0.2.2', 'port': 22}

    def remote(self, label, action, payload=None, timeout=180):
        wire_action, source = control.ControlIO._REMOTE_ACTIONS[action]
        epoch = (self.state.get(label, {}).get('epoch', self.operation['source_epoch'])
                 if source == 'current' else self.operation[source])
        action = wire_action
        request_boot = self.state.get(label, {}).get('boot_id')
        self.calls.append(('remote', label, action, epoch, request_boot, timeout))
        if label == 'A':
            boot = 'changed-a' if self.scenario == 'final-a-change' and sum(
                c[:3] == ('remote', 'A', 'probe') for c in self.calls) > 1 else A_BOOT
            return {'boot_id': boot, 'config': {'role': 'writer', 'epoch': epoch,
                    'binaries': {'trail': 'a' * 64, 'litestream': 'b' * 64},
                    'support': {'fixed': 'c' * 64}},
                    'status': {'epoch': epoch, 'healthy': self.scenario != 'final-a-unhealthy',
                               'trailbase_running': True, 'positions': cut(20)}}
        if action == 'inspect-cold':
            boot = SOURCE_BOOT if self.scenario == 'same-boot' else B_BOOT
            authority = ('current' if self.scenario == 'bad-quarantine' else
                         'stale' if self.scenario == 'retained-stale' else 'absent')
            return {'operation': self.operation['id'], 'epoch': epoch, 'boot_id': boot,
                    'authority': authority, 'cgroup': 'empty', 'mutators': 'none',
                    'services': {'node_service': 'static', 'restart': 'no',
                                 'legacy_services': 'masked'},
                    'config': {'role': 'writer', 'epoch': epoch,
                               'binaries': {'trail': 'a' * 64, 'litestream': 'b' * 64},
                               'support': {'fixed': 'c' * 64}},
                    'replica_config': 'old B replica', 'config_sha': CONFIG_SHA,
                    'replica_sha': REPLICA_SHA}
        if action == 'rejoin':
            return {'operation': self.operation['id'], 'role': 'standby',
                    'epoch': self.operation['new_epoch'], 'original_epoch': self.operation['source_epoch'],
                    'original_boot_id': B_BOOT,
                    'original_config_sha': 'f' * 64 if self.scenario == 'hash-mismatch' else CONFIG_SHA,
                    'original_replica_sha': REPLICA_SHA, 'healthy': True, 'cut': cut(1)}
        if action == 'probe':
            status = self.b_probes.pop(0) if self.b_probes else self.native_status(cut(20))
            return {'boot_id': B_BOOT,
                    'config': {'role': 'standby', 'epoch': self.operation['new_epoch'],
                               'binaries': {'trail': 'a' * 64, 'litestream': 'b' * 64},
                               'support': {'fixed': 'c' * 64}},
                    'status': status}
        raise AssertionError((label, action))

    @classmethod
    def native_status(cls, positions):
        processes = {name: True for name in DBS}
        if cls.scenario == 'incomplete-processes': processes.pop('aux')
        return {'role': 'standby', 'epoch': cls.new_epoch, 'healthy': True,
                'trailbase_running': False, 'positions': positions, 'processes': processes,
                'refusals': [], 'promotion_ready': False,
                'limitation': 'D1 transport observation only; no failover readiness or RPO bound'}


class RejoinDriverTests(unittest.TestCase):
    def fixture(self, scenario=None):
        temporary = tempfile.TemporaryDirectory()
        base = Path(temporary.name).resolve()
        root = base / 'controller'; root.mkdir(mode=0o700)
        ingress = base / 'haproxy.cfg'; ingress.write_text('route A\n')
        maintenance = base / 'maintenance'
        route_sha = hashlib.sha256(ingress.read_bytes()).hexdigest()
        with control.Journal(root) as journal:
            operation = journal.begin('B', 'A', 'd1-source-b')
            values = {
                'preflight': {'source_boot': SOURCE_BOOT, 'candidate_boot': A_BOOT},
                'select_cut': {'positions': cut(10)},
                'restore': {'cut': cut(10), 'signature': signature('old')},
                'compare': {'positions': cut(10), 'signature': signature('old'),
                            'auth_and_records': 'PASS'},
                'activate': {'probe': {'boot_id': A_BOOT, 'config': {'role': 'writer',
                    'epoch': operation['new_epoch'], 'binaries': {'trail': 'a' * 64, 'litestream': 'b' * 64},
                    'support': {'fixed': 'c' * 64}}}},
                'baseline': {'epoch': operation['new_epoch'], 'positions': cut(15),
                             'signature': signature('baseline'), 'auth_and_records': 'PASS'},
                'route': {'writer': 'A', 'epoch': operation['new_epoch'], 'config_sha': route_sha},
                'verify': {'writer': 'A', 'epoch': operation['new_epoch'], 'positions': cut(20),
                           'new_writes': {'positions': cut(20), 'signature': signature('new'),
                                          'auth_and_records': 'PASS'}},
            }
            for phase in control.D3_PHASES[:10]:
                journal.step(phase, lambda value=values.get(phase, {}): value)
        (root / operation['id']).mkdir(mode=0o700)
        maintenance.write_text(json.dumps({'operation': operation['id']})); maintenance.chmod(0o600)
        FakeIO.scenario = scenario; FakeIO.calls = []; FakeIO.b_probes = []
        FakeIO.new_epoch = operation['new_epoch']
        return temporary, root, ingress, maintenance, operation

    def run_rejoin(self, fixture):
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        with patch.object(control.time, 'sleep', return_value=None):
            result = control.rejoin({'nodes': {'B': {'address': '192.0.2.2'}}}, operation['id'],
                                    root=root, ingress=ingress, maintenance=maintenance,
                                    io_factory=FakeIO)
        return result, root, ingress, operation

    def test_no_provider_boot_success_polls_stale_positions_and_binds_distinct_boots(self):
        fixture = self.fixture()
        FakeIO.b_probes = [FakeIO.native_status(cut(19)), FakeIO.native_status(cut(20))]
        result, root, _, operation = self.run_rejoin(fixture)
        self.assertEqual(result, operation['id'])
        self.assertIn(('wait-reachable', 'B', 90), FakeIO.calls)
        inspect = next(c for c in FakeIO.calls if c[:3] == ('remote', 'B', 'inspect-cold'))
        self.assertIsNone(inspect[4])
        self.assertNotEqual(SOURCE_BOOT, A_BOOT)  # D3 source B is D2's candidate, not D2's source A.
        self.assertEqual(sum(c[:3] == ('remote', 'B', 'probe') for c in FakeIO.calls), 2)
        with control.Journal(root) as journal:
            complete = journal.db.execute('SELECT complete FROM operations WHERE id=?', (operation['id'],)).fetchone()
        self.assertEqual(complete, (1,))
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=fixture[2],
                           maintenance=fixture[3], io_factory=FakeIO)

    def test_safe_stale_authority_is_retained_but_not_required_after_reboot(self):
        fixture = self.fixture('retained-stale')
        result, _, _, operation = self.run_rejoin(fixture)
        self.assertEqual(result, operation['id'])

    def test_same_boot_and_bad_quarantine_are_persisted_and_not_replayable(self):
        for scenario in ('same-boot', 'bad-quarantine'):
            with self.subTest(scenario=scenario):
                fixture = self.fixture(scenario)
                temporary, root, ingress, maintenance, operation = fixture
                self.addCleanup(temporary.cleanup)
                before = ingress.read_bytes()
                with self.assertRaises(RuntimeError):
                    control.rejoin({'nodes': {'B': {'address': '192.0.2.2'}}}, operation['id'],
                                   root=root, ingress=ingress, maintenance=maintenance, io_factory=FakeIO)
                self.assertEqual(ingress.read_bytes(), before)
                self.assertEqual(json.loads((root / operation['id'] / 'failure.json').read_text())['phase'],
                                 'rejoin_boot')
                with self.assertRaises(RuntimeError):
                    control.rejoin({}, operation['id'], root=root, ingress=ingress,
                                   maintenance=maintenance, io_factory=FakeIO)

    def test_rejoin_result_must_preserve_inspected_original_hashes(self):
        fixture = self.fixture('hash-mismatch')
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=ingress,
                           maintenance=maintenance, io_factory=FakeIO)
        self.assertEqual(json.loads((root / operation['id'] / 'failure.json').read_text())['phase'],
                         'rejoin')

    def test_incomplete_native_process_map_fails_closed(self):
        fixture = self.fixture('incomplete-processes')
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=ingress,
                           maintenance=maintenance, io_factory=FakeIO)
        self.assertEqual(json.loads((root / operation['id'] / 'failure.json').read_text())['phase'],
                         'verify_redundancy')

    def test_final_a_change_refuses_completion(self):
        fixture = self.fixture('final-a-change')
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=ingress,
                           maintenance=maintenance, io_factory=FakeIO)
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT complete FROM operations WHERE id=?',
                                                (operation['id'],)).fetchone(), (0,))
        self.assertEqual(json.loads((root / operation['id'] / 'failure.json').read_text())['phase'],
                         'verify_redundancy')

    def test_final_a_unhealthy_refuses_completion(self):
        fixture = self.fixture('final-a-unhealthy')
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(RuntimeError):
            self.run_rejoin(fixture)
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT complete FROM operations WHERE id=?',
                                                (operation['id'],)).fetchone(), (0,))

    def test_changed_ingress_route_refuses_completion(self):
        fixture = self.fixture()
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        ingress.write_text('route B\\n')
        with self.assertRaises(RuntimeError):
            self.run_rejoin(fixture)
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT complete FROM operations WHERE id=?',
                                                (operation['id'],)).fetchone(), (0,))

    def test_power_failure_preserves_valid_a_route_and_refuses_repeat(self):
        fixture = self.fixture('power-failure')
        temporary, root, ingress, maintenance, operation = fixture
        self.addCleanup(temporary.cleanup)
        before = ingress.read_bytes()
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=ingress,
                           maintenance=maintenance, io_factory=FakeIO)
        self.assertEqual(ingress.read_bytes(), before)
        self.assertFalse(any(c[0] == 'wait-reachable' for c in FakeIO.calls))
        with self.assertRaises(RuntimeError):
            control.rejoin({}, operation['id'], root=root, ingress=ingress,
                           maintenance=maintenance, io_factory=FakeIO)

    def test_ingress_check_rejects_extra_argument_before_dispatch(self):
        with patch.object(sys, 'argv', ['control.py', 'ingress-check', 'extra']), \
                patch.object(control.os, 'geteuid', return_value=0), \
                patch.object(control, 'ingress_allowed', side_effect=AssertionError('dispatched')):
            with self.assertRaises(SystemExit): control.main()

    def test_oracle_identity_rejects_writable_internal_ancestry_and_binary_root(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            base = Path(tmp).resolve(); support = base / 'support'; binaries = base / 'bin'
            support.mkdir(mode=0o700); binaries.mkdir(mode=0o700)
            names = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                     'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                     'secrets/keys/public_key.pem')
            digests = {}
            for name in names:
                path = support / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode()); path.chmod(0o600)
                digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            binary_hashes = {}
            for name in ('trail', 'litestream'):
                path = binaries / name; path.write_bytes(name.encode()); path.chmod(0o600)
                binary_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            source = {'support': digests, 'binaries': binary_hashes}
            (support / 'migrations').chmod(0o770)
            with self.assertRaises(ValueError): recovery._oracle_identity(source, support, binaries)
            (support / 'migrations').chmod(0o700); binaries.chmod(0o770)
            with self.assertRaises(ValueError): recovery._oracle_identity(source, support, binaries)


if __name__ == '__main__':
    unittest.main()
