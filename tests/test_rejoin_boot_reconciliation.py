"""Exact failed-boot reconciliation; all operational I/O is fake."""
import copy
import datetime
import json
from pathlib import Path
import time
import unittest

from tests import test_rejoin_driver as fixtures
FakeIO, control = fixtures.FakeIO, fixtures.control


def private(path, value):
    path.write_text(json.dumps(value)); path.chmod(0o600)


class IO(FakeIO):
    original = None

    def fence(self, action, expected, label='A'):
        self.calls.append(('fence', label, action, expected))
        if action != 'inspect': raise AssertionError('power replay forbidden')
        if self.scenario == 'provider-failure': raise RuntimeError('provider unavailable')
        return {'action': 'inspect', 'state': 'running', 'target': TARGET}

    def remote(self, label, action, payload=None, epoch=None, timeout=180):
        if label == 'B' and action == 'inspect-cold':
            self.calls.append(('remote', label, action, epoch, self.state.get('B', {}).get('boot_id'), timeout))
            value = copy.deepcopy(self.original)
            if self.scenario == 'changed-cold': value['config_sha'] = 'e' * 64
            return value
        return super().remote(label, action, payload, epoch, timeout)


TARGET = dict(node='fm2', instance_id=2, provider_label='fixture-b', address='192.0.2.2', host_key='fixture-key')


class BootReconciliationTests(unittest.TestCase):
    def fixture(self, scenario=None):
        temporary, root, ingress, maintenance, op = fixtures.RejoinDriverTests().fixture(scenario)
        self.addCleanup(temporary.cleanup)
        with control.Journal(root) as journal:
            journal.continue_rejoin(op['id'])
            with self.assertRaises(RuntimeError):
                journal.step('rejoin_boot', lambda: (_ for _ in ()).throw(RuntimeError('old guard')))
        work = root / op['id']
        private(work / 'failure.json', {'phase': 'rejoin_boot', 'error': 'RuntimeError'})
        cold = FakeIO(None, {}, op, work, {}, maintenance, ingress).remote('B', 'inspect-cold', epoch=op['source_epoch'])
        IO.original = cold
        with control.Journal(root) as journal:
            value=json.loads(journal.db.execute("SELECT evidence FROM steps WHERE operation=? AND phase='preflight' AND status='done'",(op['id'],)).fetchone()[0])
            value['source_health']={'probe':{'config':cold['config']}}
            journal.db.execute("UPDATE steps SET evidence=? WHERE operation=? AND phase='preflight' AND status='done'",(json.dumps(value),op['id']));journal.db.commit()
        base = time.time_ns() - 2000000000
        stamp = datetime.datetime.fromtimestamp((base + 1000000) / 1e9, datetime.timezone.utc).isoformat()
        receipt = dict(action='power-on', target=TARGET, request={'id': 'fixture-power', 'time': stamp},
                       completion={'time': stamp}, state='running', observations=[
                           {'time': stamp, 'state': 'offline'},
                           {'time': stamp, 'state': 'running', 'identity': {
                               'instance_id': 2, 'provider_label': 'fixture-b', 'addresses': ['192.0.2.2']}}])
        for prefix, value, argv in (
            (base, receipt, ['/root/.config/hat/m1-fence-linode', 'power-on', '/etc/hat-control/target-fm2.json']),
            (base+2000000, cold, ['ssh', *control.ControlIO.SSH_FLAGS, 'root@192.0.2.2', 'hat-node'])):
            private(work / (str(prefix)+'.stdout'), value)
            private(work / (str(prefix)+'.intent.json'), {'argv': argv})
            private(work / (str(prefix)+'.outcome.json'), {'argv': argv, 'returncode': 0, 'uncertain': False})
        FakeIO.calls = []
        config = {'nodes': {'B': {'address': '192.0.2.2'}}, 'fence_targets': {'B': TARGET}}
        args = dict(root=root, ingress=ingress, maintenance=maintenance, io_factory=IO)
        return root, op, config, args

    def test_reconciles_only_completed_boot_then_rejoins_once_without_power(self):
        root, op, config, args = self.fixture()
        self.assertEqual(control.reconcile_rejoin_boot(config, op['id'], **args), op['id'])
        self.assertEqual(sum(c[:3] == ('remote','B','rejoin') for c in FakeIO.calls), 1)
        self.assertTrue(all(c[2] == 'inspect' for c in FakeIO.calls if c[0] == 'fence'))
        self.assertTrue((root/op['id']/'failure.before-reconciliation-rejoin-boot.json').is_file())
        with control.Journal(root) as journal:
            self.assertEqual(journal.db.execute('SELECT complete FROM operations WHERE id=?',(op['id'],)).fetchone(), (1,))
            self.assertEqual(journal.db.execute("SELECT COUNT(*) FROM steps WHERE operation=? AND phase='rejoin_boot'",(op['id'],)).fetchone(), (2,))
        with self.assertRaises(RuntimeError): control.reconcile_rejoin_boot(config, op['id'], **args)

    def test_changed_or_failed_fresh_checks_preserve_route_and_refuse_repeat(self):
        for scenario in ('changed-cold', 'provider-failure'):
            with self.subTest(scenario=scenario):
                root, op, config, args = self.fixture(scenario)
                before = args['ingress'].read_bytes()
                with self.assertRaises(RuntimeError): control.reconcile_rejoin_boot(config, op['id'], **args)
                self.assertEqual(args['ingress'].read_bytes(), before)
                self.assertFalse(any(c[:3] == ('remote','B','rejoin') for c in FakeIO.calls))
                self.assertTrue((root/op['id']/'failure.json').is_file())
                with self.assertRaises(RuntimeError): control.reconcile_rejoin_boot(config, op['id'], **args)

    def test_missing_ambiguous_and_wrong_target_evidence_refuse_before_io(self):
        for scenario in ('missing', 'duplicate', 'wrong-target', 'wrong-address', 'untyped-id'):
            with self.subTest(scenario=scenario):
                root, op, config, args = self.fixture()
                work = root / op['id']
                path = next(p for p in work.glob('*.stdout') if json.loads(p.read_text()).get('action') == 'power-on')
                if scenario == 'missing': path.unlink()
                elif scenario == 'duplicate':
                    prefix = '999999999999999999'
                    for suffix in ('.stdout','.intent.json','.outcome.json'):
                        private(work/(prefix+suffix), json.loads(path.with_suffix(suffix).read_text()))
                else:
                    value = json.loads(path.read_text())
                    if scenario == 'wrong-target': value['target'] = value['target'] | {'instance_id': 3}
                    elif scenario == 'wrong-address': value['observations'][-1]['identity']['addresses'] = ['192.0.2.99']
                    else: value['observations'][-1]['identity']['instance_id'] = 2.0
                    private(path,value)
                with self.assertRaises(RuntimeError): control.reconcile_rejoin_boot(config, op['id'], **args)
                self.assertEqual(FakeIO.calls, [])


if __name__ == '__main__': unittest.main()
