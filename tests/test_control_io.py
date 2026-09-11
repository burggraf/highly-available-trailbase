import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control
import recovery


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
        root = Path(tempfile.mkdtemp()).resolve()
        journal = JournalStub()
        config = config or {'nodes': {'A': {'address': 'fm1.example'}}}
        operation = operation or {'id': 'a' * 32, 'source': 'A', 'target': 'B',
                                 'source_epoch': 'd1-source', 'new_epoch': 'd1-' + 'a' * 32}
        return control.ControlIO(journal, config, operation, root,
                                 state or {'A': {'boot_id': 'boot-a'}}), root, journal

    def test_command_records_private_result_and_timeout_uncertainty(self):
        io, root, journal = self.make_io()
        failed = Mock(returncode=3)
        failed.poll.return_value = 3
        failed.communicate.return_value = (b'', b'')
        with patch.object(control.subprocess, 'Popen', return_value=failed):
            with self.assertRaises(RuntimeError):
                io.command(['fake', 'arg'], data=b'secret')
        outcomes = list(root.glob('*.outcome.json'))
        self.assertEqual(json.loads(outcomes[0].read_text())['returncode'], 3)
        self.assertNotIn('secret', outcomes[0].read_text())
        timed_out = Mock(returncode=-9)
        timed_out.poll.return_value = None
        timed_out.communicate.side_effect = subprocess.TimeoutExpired(['fake'], 1)
        with patch.object(control.subprocess, 'Popen', return_value=timed_out):
            with self.assertRaises(subprocess.TimeoutExpired):
                io.command(['fake'])
        timeout = [json.loads(p.read_text()) for p in root.glob('*.outcome.json')
                   if json.loads(p.read_text()).get('uncertain')]
        self.assertEqual(len(timeout), 1)
        self.assertGreaterEqual(journal.checks, 4)

    def test_command_boundary_failure_keeps_only_durable_intent(self):
        io, root, _ = self.make_io()
        def fail(_argv):
            raise RuntimeError('pre-spawn boundary')
        io._before_command_spawn = fail
        with patch.object(control.subprocess, 'run') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'pre-spawn boundary'):
                io.command(['systemd-run', '--unit=one'])
        spawn.assert_not_called()
        intents = list(root.glob('*.intent.json'))
        self.assertEqual(len(intents), 1)
        self.assertEqual(json.loads(intents[0].read_text())['argv'],
                         ['systemd-run', '--unit=one'])
        self.assertEqual(list(root.glob('*.stdout')), [])
        self.assertEqual(list(root.glob('*.stderr')), [])
        self.assertEqual(list(root.glob('*.outcome.json')), [])

    def test_restore_fsync_boundary_failure_preserves_created_request(self):
        io, root, _ = self.make_io()
        seen = []
        def fail(label, path):
            seen.append((label, Path(path).name))
            if label == 'acceptance-request.file':
                raise RuntimeError('fsync boundary')
        io._before_fsync = lambda label, path: seen.append(('before', label))
        io._after_fsync = fail
        with self.assertRaisesRegex(RuntimeError, 'fsync boundary'):
            io._durable_bytes(root / 'acceptance-request.json', b'{}', label='acceptance-request')
        self.assertEqual((root / 'acceptance-request.json').read_bytes(), b'{}')
        self.assertEqual(seen[0], ('before', 'acceptance-request.file'))

    def test_restore_copy_boundary_hook_is_private_and_preserves_source(self):
        io, root, _ = self.make_io()
        source = root / 'source.json'; source.write_bytes(b'copy'); source.chmod(0o600)
        destination = root / 'destination.json'
        io._before_fsync = lambda label, path: (_ for _ in ()).throw(RuntimeError('copy fsync')) \
            if label == 'copy.file' else None
        with self.assertRaisesRegex(RuntimeError, 'copy fsync'):
            io._copy_bound(source, destination, 0o600, os.geteuid(), os.getegid(), hashlib.sha256(b'copy').hexdigest())
        self.assertEqual(source.read_bytes(), b'copy')
        self.assertTrue(destination.exists())

    def test_command_runs_only_safe_local_subprocess_integration(self):
        io, _, _ = self.make_io()
        self.assertEqual(io.command([sys.executable, '-c', 'print("safe")']), b'safe\n')

    def test_remote_derives_epoch_from_fixed_action(self):
        io, _, _ = self.make_io({'nodes': {'A': {'address': 'logical-a'}}})
        calls = []
        io.command = lambda argv, data=None, timeout=180: calls.append((argv, data, timeout)) or b'{"ok": true}'
        self.assertEqual(io.remote('A', 'probe-source'), {'ok': True})
        self.assertEqual(io.remote('A', 'probe-new'), {'ok': True})
        source_request = json.loads(calls[0][1])
        new_request = json.loads(calls[1][1])
        self.assertEqual((source_request['action'], source_request['epoch']), ('probe', 'd1-source'))
        self.assertEqual((new_request['action'], new_request['epoch']), ('probe', 'd1-' + 'a' * 32))
        self.assertEqual(source_request['boot_id'], 'boot-a')
        self.assertEqual(calls[0][0][-2:], ['root@logical-a', 'hat-node'])
        self.assertIn('StrictHostKeyChecking=yes', calls[0][0])
        self.assertEqual(calls[0][2], 180)
        with self.assertRaises(ValueError):
            io.remote('A', 'unknown-action')

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


    def test_committed_preflight_authority_supplies_reconciliation_manifests(self):
        names = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                 'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                 'secrets/keys/public_key.pem')
        support = {name: 'b' * 64 for name in names}
        binaries = {'trail': 'c' * 64, 'litestream': 'd' * 64}
        io, _, _ = self.make_io(state={'B': {'boot_id': 'retained-only'}})
        authority = {'schema':'hat-restore-input-authority-1','operation':io.operation['id'],
                     'origin':'d2-preflight','ledger':{'path':'/var/lib/hat-control/'+io.operation['id']+'/ledger.jsonl',
                     'device':1,'inode':2,'mode':384,'uid':0,'links':1,'bytes':1,'sha256':'a'*64},
                     'support':support,'binaries':binaries}
        io.journal.db = MagicMock()
        io.journal.db.execute.return_value.fetchone.return_value = (json.dumps({'ledger_authority': authority}),)
        self.assertEqual(io._authorized_manifests(), (names, support, binaries))
        io.journal.db.execute.return_value.fetchone.return_value = (json.dumps({'ledger_authority': authority | {'support': {}}}),)
        with self.assertRaises(ValueError): io._authorized_manifests()
        io.journal.db.execute.return_value.fetchone.return_value = None
        with self.assertRaises(ValueError): io._authorized_manifests()

    def test_fresh_writes_authority_is_canonical_and_required(self):
        names = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                 'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                 'secrets/keys/public_key.pem')
        support = {name: 'b' * 64 for name in names}
        binaries = {'trail': 'c' * 64, 'litestream': 'd' * 64}
        io, root, journal = self.make_io(state={'A': {'config': {
            'support': support, 'binaries': binaries}}})
        journal.pending = True; journal.next = 9
        fresh = root / 'new-writes.jsonl'
        fresh.write_bytes(b'{"fresh":true}\n'); fresh.chmod(0o600)
        authority = io.authorize_fresh_writes(fresh)
        sidecar = root / 'new-writes-input-authority.json'
        self.assertEqual(recovery.parse_canonical_json(sidecar.read_bytes()), authority)
        self.assertEqual((authority['origin'], authority['operation'], authority['ledger']['path']),
                         ('current-verify-exclusive', io.operation['id'], str(fresh)))
        self.assertEqual((authority['support'], authority['binaries']), (support, binaries))

        account = type('Account', (), {'pw_uid': os.geteuid(), 'pw_gid': os.getegid()})()
        with patch.object(control.pwd, 'getpwnam', return_value=account), \
             patch.object(io, '_installed_manifest', side_effect=[support, binaries]), \
             patch.object(recovery, '_authority'):
            request, _ = io._acceptance_request(
                'new-writes', 'config', {'main': 1, 'session': 1, 'aux': 1}, fresh, None)
        self.assertEqual(request['inputs']['ledger_authority'], authority)

        other, other_root, other_journal = self.make_io(state={'A': {'config': {
            'support': support, 'binaries': binaries}}})
        other_journal.pending = True; other_journal.next = 9
        other_fresh = other_root / 'new-writes.jsonl'
        other_fresh.write_bytes(b'{"fresh":true}\n'); other_fresh.chmod(0o600)
        with patch.object(control.pwd, 'getpwnam', return_value=account), \
             patch.object(other, '_installed_manifest', side_effect=[support, binaries]):
            with self.assertRaises(ValueError):
                other._acceptance_request('new-writes', 'config',
                    {'main': 1, 'session': 1, 'aux': 1}, other_fresh, None)
        self.assertFalse((other_root / 'new-writes-input-authority.json').exists())

    def test_fresh_writes_authority_rejects_replacement_and_duplicate_sidecar(self):
        names = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                 'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                 'secrets/keys/public_key.pem')
        support = {name: 'b' * 64 for name in names}
        binaries = {'trail': 'c' * 64, 'litestream': 'd' * 64}
        account = type('Account', (), {'pw_uid': os.geteuid(), 'pw_gid': os.getegid()})()
        for mutation in ('replacement', 'duplicate'):
            with self.subTest(mutation=mutation):
                io, root, journal = self.make_io(state={'A': {'config': {
                    'support': support, 'binaries': binaries}}})
                journal.pending = True; journal.next = 9
                fresh = root / 'new-writes.jsonl'
                fresh.write_bytes(b'{"fresh":true}\n'); fresh.chmod(0o600)
                io.authorize_fresh_writes(fresh)
                if mutation == 'replacement':
                    fresh.rename(root / 'old')
                    fresh.write_bytes(b'{"fresh":true}\n'); fresh.chmod(0o600)
                else:
                    sidecar = root / 'new-writes-input-authority.json'
                    sidecar.unlink(); sidecar.write_bytes(b'{"schema":"one","schema":"two"}')
                    sidecar.chmod(0o600)
                with patch.object(control.pwd, 'getpwnam', return_value=account), \
                     patch.object(io, '_installed_manifest', side_effect=[support, binaries]), \
                     patch.object(recovery, '_authority'):
                    with self.assertRaises(ValueError):
                        io._acceptance_request('new-writes', 'config',
                            {'main': 1, 'session': 1, 'aux': 1}, fresh, None)

    def test_reconciliation_request_requires_durable_boundary_and_unused_sidecar(self):
        class Reached(Exception):
            pass

        for phase, position, filename, action in (
                ('reconciled-compare', 5, 'reconciliation.json', 'accept-checked-comparison'),
                ('verification-baseline', 9, 'verification-reconciliation.json', 'verification-only')):
            with self.subTest(phase=phase):
                io, root, journal = self.make_io()
                journal.pending = False; journal.next = position
                journal._boundary = Mock(return_value=(dict(io.operation), {}))
                (root / filename).write_bytes(recovery.canonical_json({
                    'operation': io.operation['id'], 'action': action, 'failure_sha': 'f' * 64}))
                (root / filename).chmod(0o600)
                with patch.object(control.pwd, 'getpwnam', side_effect=Reached):
                    with self.assertRaises(Reached):
                        io._acceptance_request(phase, 'config',
                            {'main': 1, 'session': 1, 'aux': 1}, root / 'ledger.jsonl', None)
                journal._boundary.assert_called_once_with(io.operation['id'], position)

                for bad in ('pending', 'sidecar', 'request', 'result', 'later'):
                    with self.subTest(bad=bad):
                        journal.pending = bad == 'pending'
                        journal._boundary.reset_mock()
                        journal._boundary.side_effect = RuntimeError('later') if bad == 'later' else None
                        journal._boundary.return_value = (dict(io.operation), {})
                        sidecar = root / filename
                        sidecar.write_bytes(recovery.canonical_json({
                            'operation': '0' * 32 if bad == 'sidecar' else io.operation['id'],
                            'action': action, 'failure_sha': 'f' * 64}))
                        replay = root / (phase + '-acceptance-' + ('request' if bad == 'request' else 'result') + '.json')
                        if bad in ('request', 'result'): replay.write_bytes(b'{}')
                        reached = Mock(side_effect=Reached)
                        with patch.object(control.pwd, 'getpwnam', reached):
                            with self.assertRaises(RuntimeError):
                                io._acceptance_request(phase, 'config',
                                    {'main': 1, 'session': 1, 'aux': 1}, root / 'ledger.jsonl', None)
                        reached.assert_not_called()
                        if replay.exists(): replay.unlink()

    def _oracle_copy_fixture(self, fault=False):
        io, _, _ = self.make_io()
        positions = {'main': 1, 'session': 1, 'aux': 1}
        identity = (1, 2, 0o100600, os.geteuid(), os.getegid(), 1, 7)
        ledger = {'path': '/tmp/ledger.jsonl', 'device': 1, 'inode': 2, 'mode': 0o600,
                  'uid': os.geteuid(), 'links': 1, 'bytes': 7, 'sha256': 'a' * 64}
        inputs = {'replica_config_sha256': control.hashlib.sha256(b'config').hexdigest(),
                  'ledger_authority': {'ledger': ledger}, 'support': {}, 'binaries': {}}
        if fault:
            inputs['fault_ledger_sha256'] = 'b' * 64
        request = {'phase': 'compare', 'positions': positions,
                   'profile': 'recovery-comparison' if fault else 'comparison', 'inputs': inputs}
        io._acceptance_request = Mock(return_value=(request, b'{}', [], identity))
        return io, positions

    def test_oracle_records_exact_exclusive_artifact_order_with_and_without_fault(self):
        for fault in (False, True):
            with self.subTest(fault=fault):
                io, positions = self._oracle_copy_fixture(fault)
                events, fds = [], {}
                next_fd = iter(range(100, 130))
                area = Path('/var/lib/hat-oracle') / ('d2-' + io.operation['id'] + '-compare')
                request_path = io.work / 'compare-acceptance-request.json'
                def opened(path, flags, *args, **kwargs):
                    fd = next(next_fd); fds[fd] = Path(path)
                    if Path(path) == request_path:
                        self.assertTrue(flags & os.O_EXCL); events.append('operation-request')
                    elif Path(path).name == 'replica.yml':
                        self.assertTrue(flags & os.O_EXCL); events.append('replica.yml')
                    return fd
                def synced(fd):
                    path = fds.get(fd)
                    if path == request_path: events.append('request-fsync')
                    elif path == io.work and 'replica.yml' not in events: events.append('work-fsync')
                    elif path == control.ORACLE_ROOT: events.append('oracle-root-fsync')
                    elif path == area: events.append('area-fsync')
                def copied(source, destination, *args, **kwargs):
                    events.append(Path(destination).name)
                authorized = MagicMock(); authorized.read.return_value = b'ledger\n'
                with patch.object(io, 'command', side_effect=RuntimeError('stop')) as command, \
                     patch.object(control.pwd, 'getpwnam', return_value=type('Account', (), {'pw_uid': os.geteuid(), 'pw_gid': os.getegid()})()), \
                     patch.object(control.descriptor.DescriptorAuthority, 'open_file', return_value=authorized), \
                     patch.object(recovery, '_protected_ledger'), \
                     patch.object(control, 'oracle_directory'), patch.object(Path, 'mkdir'), \
                     patch.object(control.os, 'chown'), patch.object(control.os, 'open', side_effect=opened), \
                     patch.object(control.os, 'write', side_effect=lambda fd, raw: len(raw)), patch.object(control.os, 'fchmod'), patch.object(control.os, 'fchown'), \
                     patch.object(control.os, 'fsync', side_effect=synced), patch.object(control.os, 'close'), \
                     patch.object(control, '_copy_bound_input', side_effect=copied), \
                     patch.object(io, '_reopen_exact_bytes'), patch.object(control, '_open_held_inputs', return_value=[]):
                    with self.assertRaisesRegex(RuntimeError, 'stop'):
                        io.oracle('compare', 'config', positions, '/tmp/ledger.jsonl',
                                  '/tmp/fault.jsonl' if fault else None)
                expected = ['operation-request', 'request-fsync', 'work-fsync',
                            'oracle-root-fsync', 'area-fsync', 'replica.yml',
                            'area-fsync', 'ledger.jsonl']
                if fault: expected.append('fault-ledger.jsonl')
                expected += ['acceptance-request.json']
                self.assertEqual([event for event in events if event in expected], expected)
                command.assert_called_once()

    def test_oracle_request_fsync_failure_creates_no_oracle_area_or_command(self):
        io, positions = self._oracle_copy_fixture()
        request_path = io.work / 'compare-acceptance-request.json'
        fds = {}
        def opened(path, flags, *args, **kwargs):
            fd = 780 + len(fds); fds[fd] = Path(path); return fd
        def synced(fd):
            if fds.get(fd) == request_path: raise OSError('request fsync')
        authorized = MagicMock(); authorized.read.return_value = b'ledger\n'
        with patch.object(io, 'command') as command, \
             patch.object(control.pwd, 'getpwnam', return_value=type('Account', (), {'pw_uid': os.geteuid(), 'pw_gid': os.getegid()})()), \
             patch.object(control.descriptor.DescriptorAuthority, 'open_file', return_value=authorized), \
             patch.object(recovery, '_protected_ledger'), \
             patch.object(control, 'oracle_directory') as make_area, \
             patch.object(control.os, 'open', side_effect=opened), \
             patch.object(control.os, 'write', side_effect=lambda fd, raw: len(raw)), patch.object(control.os, 'fsync', side_effect=synced), \
             patch.object(control.os, 'close'), patch.object(control, '_copy_bound_input') as copied:
            with self.assertRaisesRegex(OSError, 'request fsync'):
                io.oracle('compare', 'config', positions, '/tmp/ledger.jsonl')
        make_area.assert_not_called(); copied.assert_not_called(); command.assert_not_called()

    def test_oracle_preexisting_replica_refuses_without_command_or_replay(self):
        io, positions = self._oracle_copy_fixture()
        authorized = MagicMock(); authorized.read.return_value = b'ledger\n'
        with patch.object(io, 'command') as command, \
             patch.object(control.pwd, 'getpwnam', return_value=type('Account', (), {'pw_uid': os.geteuid(), 'pw_gid': os.getegid()})()), \
             patch.object(control.descriptor.DescriptorAuthority, 'open_file', return_value=authorized), \
             patch.object(recovery, '_protected_ledger'), patch.object(control, 'oracle_directory'), \
             patch.object(Path, 'mkdir'), patch.object(Path, 'exists', return_value=True), \
             patch.object(control.os, 'chown'), patch.object(control.os, 'open', side_effect=FileExistsError), \
             patch.object(control, '_copy_bound_input') as copied:
            with self.assertRaises(FileExistsError):
                io.oracle('compare', 'config', positions, '/tmp/ledger.jsonl')
        command.assert_not_called(); copied.assert_not_called()

if __name__ == '__main__':
    unittest.main()
