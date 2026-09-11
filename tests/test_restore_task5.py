"""Task5 crash-boundary matrices for restore controller durability."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control


class _Journal:
    def check_authority(self):
        return None


class _Process:
    returncode = 0

    def __init__(self):
        self.killed = False
        self.waited = False

    def communicate(self, input=None, timeout=None):
        if input == b'after-start':
            raise OSError('communication failed')
        return b'', b''

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


class RestoreTask5Tests(unittest.TestCase):
    def io(self):
        root = Path(tempfile.mkdtemp()).resolve()
        operation = {'id': 'a' * 32, 'source': 'A', 'target': 'B',
                     'source_epoch': 'd1-source', 'new_epoch': 'd1-' + 'a' * 32}
        return control.ControlIO(_Journal(), {}, operation, root, {}) , root

    def test_command_boundary_matrix_distinguishes_before_and_after_start(self):
        for boundary in ('pre-spawn', 'post-start', 'communication'):
            with self.subTest(boundary=boundary):
                io, root = self.io()
                process = _Process()
                if boundary == 'pre-spawn':
                    io._before_command_spawn = lambda argv: (_ for _ in ()).throw(RuntimeError('pre-spawn'))
                elif boundary == 'post-start':
                    io._after_command_start = lambda child: (_ for _ in ()).throw(RuntimeError('post-start'))
                with patch.object(control.subprocess, 'Popen', return_value=process) as spawn:
                    with self.assertRaises((RuntimeError, OSError)):
                        io.command([sys.executable, '-c', 'pass'], data=b'after-start')
                if boundary == 'pre-spawn':
                    spawn.assert_not_called()
                    self.assertEqual(list(root.glob('*.stdout')), [])
                    self.assertEqual(list(root.glob('*.stderr')), [])
                    self.assertEqual(list(root.glob('*.outcome.json')), [])
                else:
                    outcomes = list(root.glob('*.outcome.json'))
                    self.assertEqual(len(outcomes), 1)
                    self.assertTrue(json.loads(outcomes[0].read_text())['uncertain'])
                    self.assertEqual(len(list(root.glob('*.stdout'))), 1)
                    self.assertEqual(len(list(root.glob('*.stderr'))), 1)

    def test_command_timeout_kills_and_retains_uncertain_evidence(self):
        io, root = self.io()
        process = _Process()
        process.communicate = lambda input=None, timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(['command'], timeout))
        with patch.object(control.subprocess, 'Popen', return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired): io.command(['command'])
        self.assertTrue(process.killed)
        self.assertTrue(process.waited)
        outcome = json.loads(next(root.glob('*.outcome.json')).read_text())
        self.assertTrue(outcome['uncertain'])

    def test_durable_bytes_handles_partial_writes_and_reopens_exact_hash(self):
        io, root = self.io()
        raw = b'partial durable oracle replica configuration'
        real_write = os.write
        calls = []

        def partial(fd, value):
            calls.append(len(value))
            return real_write(fd, value[:max(1, len(value) // 2)])

        with patch.object(control.os, 'write', side_effect=partial):
            io._durable_bytes(root / 'replica.yml', raw, label='replica-config')
        self.assertGreater(len(calls), 1)
        self.assertEqual((root / 'replica.yml').read_bytes(), raw)

    def test_private_command_seams_are_present(self):
        self.assertTrue(hasattr(control.ControlIO, '_after_command_start'))


if __name__ == '__main__':
    unittest.main()
