import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control


class JournalStub:
    def __init__(self):
        self.checks = 0

    def check_authority(self):
        self.checks += 1


def target(node='fm1', address='fm1.example'):
    return {'node': node, 'instance_id': 7, 'provider_label': node,
            'address': address, 'host_key': 'SHA256:key'}


class ControlIOTests(unittest.TestCase):
    def make_io(self, config=None, state=None, operation=None):
        root = Path(tempfile.mkdtemp())
        journal = JournalStub()
        config = config or {'nodes': {'A': {'address': 'fm1.example'}}}
        operation = operation or {'id': 'a' * 32, 'source': 'A', 'target': 'B',
                                 'source_epoch': 'd1-source'}
        return control.ControlIO(journal, config, operation, root,
                                 state or {'A': {'boot_id': 'boot-a'}}), root, journal

    def test_command_records_private_result_and_timeout_uncertainty(self):
        io, root, journal = self.make_io()
        with patch.object(control.subprocess, 'run', return_value=subprocess.CompletedProcess([], 3)):
            with self.assertRaises(RuntimeError):
                io.command(['fake', 'arg'], data=b'secret')
        outcomes = list(root.glob('*.outcome.json'))
        self.assertEqual(json.loads(outcomes[0].read_text())['returncode'], 3)
        self.assertNotIn('secret', outcomes[0].read_text())
        with patch.object(control.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['fake'], 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                io.command(['fake'])
        timeout = [json.loads(p.read_text()) for p in root.glob('*.outcome.json')
                   if json.loads(p.read_text()).get('uncertain')]
        self.assertEqual(len(timeout), 1)
        self.assertGreaterEqual(journal.checks, 4)

    def test_command_runs_only_safe_local_subprocess_integration(self):
        io, _, _ = self.make_io()
        self.assertEqual(io.command([sys.executable, '-c', 'print("safe")']), b'safe\n')

    def test_remote_uses_source_epoch_boot_and_pinned_dispatcher(self):
        io, _, _ = self.make_io({'nodes': {'A': {'address': 'logical-a'}}})
        calls = []
        io.command = lambda argv, data=None, timeout=180: calls.append((argv, data, timeout)) or b'{"ok": true}'
        self.assertEqual(io.remote('A', 'probe', epoch=None), {'ok': True})
        argv, data, timeout = calls[0]
        request = json.loads(data)
        self.assertEqual(request['epoch'], 'd1-source')
        self.assertEqual(request['boot_id'], 'boot-a')
        self.assertEqual(argv[-2:], ['root@logical-a', 'hat-node'])
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertEqual(timeout, 180)

    def test_wait_reachable_uses_pinned_address_and_closes_probe_socket(self):
        io, _, journal = self.make_io({'nodes': {'B': {'address': '192.0.2.2'}}},
                                      {'B': {}})
        connection = Mock()
        with patch.object(control.socket, 'create_connection', return_value=connection) as connect:
            self.assertEqual(io.wait_reachable('B', timeout=90),
                             {'label': 'B', 'address': '192.0.2.2', 'port': 22})
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], ('192.0.2.2', 22))
        connection.close.assert_called_once_with()
        self.assertEqual(journal.checks, 1)

        with patch.object(control.socket, 'create_connection', side_effect=TimeoutError), \
                patch.object(control.time, 'monotonic', side_effect=[0, 0, 2]):
            with self.assertRaises(RuntimeError): io.wait_reachable('B', timeout=1)

    def test_producer_death_requires_loaded_inactive_unit_and_zero_pid(self):
        io, _, _ = self.make_io()
        unit = 'hat-d3-client-' + '1' * 32 + '.service'
        cgroup = '/sys/fs/cgroup/system.slice/' + unit
        io.command = lambda argv, data=None, timeout=180: b'LoadState=loaded\nMainPID=0\nActiveState=inactive\nSubState=dead\n'
        self.assertEqual(io.producer_stopped(unit, cgroup)['cgroup'], 'absent')
        for raw in (b'LoadState=not-found\nMainPID=0\nActiveState=inactive\nSubState=dead\n',
                    b'LoadState=loaded\nMainPID=42\nActiveState=active\nSubState=running\n'):
            io.command = lambda argv, data=None, timeout=180, raw=raw: raw
            with self.assertRaises(RuntimeError): io.producer_stopped(unit, cgroup)
        with self.assertRaises(ValueError): io.producer_stopped('other.service', cgroup)

    def test_fence_target_requires_trusted_pin_label_and_address(self):
        pinned = target()
        config = {'nodes': {'A': {'address': 'fm1.example'}}, 'fence_target': pinned}
        io, root, _ = self.make_io(config)
        file_path = root / 'target.json'
        file_path.write_text(json.dumps(pinned))
        with patch.object(control, 'Path', return_value=file_path), patch.object(control, 'private_file'):
            self.assertEqual(io._fence_target('A')[1], pinned)
            file_path.write_text(json.dumps(target(address='wrong.example')))
            with self.assertRaises(ValueError):
                io._fence_target('A')
            with self.assertRaises(ValueError):
                io._fence_target('C')

        b = target('fm2', 'fm2.example')
        config = {'nodes': {'B': {'address': 'fm2.example'}}, 'fence_targets': {'B': b}}
        io, root, _ = self.make_io(config)
        file_path = root / 'target.json'
        file_path.write_text(json.dumps(b))
        with patch.object(control, 'Path', return_value=file_path), patch.object(control, 'private_file'):
            self.assertEqual(io._fence_target('B')[1], b)
            config['fence_targets']['B'] = target('fm2', 'not-logical')
            with self.assertRaises(ValueError):
                io._fence_target('B')


if __name__ == '__main__':
    unittest.main()
