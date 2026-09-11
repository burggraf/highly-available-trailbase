import hashlib
from pathlib import Path
from types import SimpleNamespace
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control
import recovery


class Held:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class Journal:
    pending = True
    next = 5

    def check_authority(self):
        pass


class RestoreTask34FdCleanupTests(unittest.TestCase):
    def test_top_level_manifest_recheck_accepts_then_rejects_replacement(self):
        for mode, name in ((0o640, 'config.textproto'), (0o755, 'trail'), (0o755, 'litestream')):
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp(dir=Path.cwd()))
                item = root / name
                item.write_bytes(b'fixed')
                item.chmod(mode)
                io = control.ControlIO.__new__(control.ControlIO)
                manifest, held = io._installed_manifest(
                    root, (name,), os.geteuid(), os.getegid(), mode, hold=True)
                try:
                    io._recheck_installed_manifest(root, (name,), held)
                    item.rename(root / 'old')
                    item.write_bytes(b'fixed')
                    item.chmod(mode)
                    with self.assertRaises(ValueError):
                        io._recheck_installed_manifest(root, (name,), held)
                finally:
                    for authority in reversed(held):
                        authority.close()

    def _acceptance_io(self):
        operation = {'id': 'a' * 32, 'source': 'A', 'target': 'B',
                     'source_epoch': 'd1-source', 'new_epoch': 'd1-' + 'a' * 32}
        support_names = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
                         'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                         'secrets/keys/public_key.pem')
        support = {name: 'b' * 64 for name in support_names}
        binaries = {'trail': 'c' * 64, 'litestream': 'd' * 64}
        io = control.ControlIO(Journal(), {}, operation, Path(tempfile.mkdtemp()),
                               {'A': {'config': {'support': support, 'binaries': binaries}}})
        account = SimpleNamespace(pw_gid=os.getegid(), pw_uid=os.geteuid())
        return io, account, support, binaries

    def test_acceptance_request_closes_support_on_binary_acquisition_failure(self):
        io, account, support, binaries = self._acceptance_io()
        first = Held()
        with patch.object(control.pwd, 'getpwnam', return_value=account), \
             patch.object(io, '_installed_manifest', side_effect=[(support, [first]), RuntimeError('binary')]):
            with self.assertRaisesRegex(RuntimeError, 'binary'):
                io._acceptance_request('compare', 'config',
                                       {'main': 1, 'session': 1, 'aux': 1},
                                       '/tmp/ledger.jsonl', None, hold_installed=True)
        self.assertEqual(first.closed, 1)

    def test_acceptance_request_closes_holds_on_ledger_and_validation_failure(self):
        for failure in ('ledger', 'validation'):
            with self.subTest(failure=failure):
                io, account, support, binaries = self._acceptance_io()
                first, second = Held(), Held()
                installed = [(support, [first]), (binaries, [second])]
                selected = SimpleNamespace(identity=(1, 2, 0o100600, os.geteuid(), os.getegid(), 1, 1),
                                           sha256='a' * 64)
                context = Mock()
                context.__enter__ = Mock(return_value=selected)
                context.__exit__ = Mock(return_value=False)
                with patch.object(control.pwd, 'getpwnam', return_value=account), \
                     patch.object(io, '_installed_manifest', side_effect=installed), \
                     patch.object(control.descriptor.DescriptorAuthority, 'open_file',
                                  side_effect=(RuntimeError('ledger') if failure == 'ledger' else None)), \
                     patch.object(recovery, 'validate_acceptance_request',
                                  side_effect=(ValueError('validation') if failure == 'validation' else None)):
                    if failure == 'ledger':
                        expected = RuntimeError
                    else:
                        expected = ValueError
                    with self.assertRaises(expected):
                        io._acceptance_request('compare', 'config',
                                               {'main': 1, 'session': 1, 'aux': 1},
                                               '/tmp/ledger.jsonl', None, hold_installed=True)
                self.assertEqual(first.closed, 1)
                self.assertEqual(second.closed, 1)

    def test_oracle_closes_installed_holds_on_profile_and_config_validation(self):
        positions = {'main': 1, 'session': 1, 'aux': 1}
        for request in (
                {'phase': 'wrong', 'positions': positions},
                {'phase': 'compare', 'positions': positions, 'profile': 'comparison',
                 'inputs': {'replica_config_sha256': '0' * 64}}):
            with self.subTest(request=request):
                io, _, _, _ = self._acceptance_io()
                held = Held()
                value = {'phase': request['phase'], 'positions': request['positions'],
                         'profile': request.get('profile', 'comparison'),
                         'inputs': request.get('inputs', {})}
                io._acceptance_request = Mock(return_value=(value, b'{}', [held], (1, 2, 0o100600, 0, 0, 1, 1)))
                with self.assertRaises(ValueError):
                    io.oracle('compare', 'config', positions, '/tmp/ledger.jsonl')
                self.assertEqual(held.closed, 1)

    def test_held_input_acquisition_closes_prior_authorities_on_nth_failure(self):
        first, second = Held(), Held()
        opener = Mock(side_effect=[first, second, RuntimeError('nth input')])
        specs = [('one', 0, 0, 0o600, 1), ('two', 0, 0, 0o600, 1),
                 ('three', 0, 0, 0o600, 1)]
        with patch.object(control.descriptor.DescriptorAuthority, 'open_file', opener):
            with self.assertRaisesRegex(RuntimeError, 'nth input'):
                control._open_held_inputs(specs)
        self.assertEqual(first.closed, 1)
        self.assertEqual(second.closed, 1)


if __name__ == '__main__':
    unittest.main()
