"""Task5 crash-boundary matrices for restore controller durability."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control
import recovery


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

    def poll(self):
        return -9 if self.killed else None

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

    def test_recovery_private_writer_rejects_nonpositive_writes(self):
        for result in (0, -1):
            with self.subTest(result=result):
                root = Path(tempfile.mkdtemp())
                with patch.object(recovery.os, 'write', return_value=result) as write:
                    with self.assertRaises(OSError):
                        recovery._write_private(root / 'artifact', b'payload')
                self.assertEqual(write.call_count, 1)

    def test_recovery_private_writer_reopens_exact_partial_bytes(self):
        root = Path(tempfile.mkdtemp())
        raw = b'exact partial bytes'
        real_write = os.write
        calls = []

        def partial(fd, value):
            calls.append(bytes(value))
            return real_write(fd, value[:1])

        with patch.object(recovery.os, 'write', side_effect=partial):
            recovery._write_private(root / 'artifact', raw)
        self.assertGreaterEqual(len(calls), len(raw))
        self.assertEqual((root / 'artifact').read_bytes(), raw)

    def test_nonzero_command_failure_survives_outcome_write_failure(self):
        io, root = self.io()
        process = _Process(); process.returncode = 7
        original = io._durable_json

        def fail_outcome(path, value, label='json'):
            if label == 'command-outcome':
                raise OSError('outcome fsync')
            return original(path, value, label=label)

        with patch.object(control.subprocess, 'Popen', return_value=process), \
             patch.object(io, '_durable_json', side_effect=fail_outcome):
            with self.assertRaisesRegex(RuntimeError, 'command failed'):
                io.command(['command'])
        self.assertEqual(process.returncode, 7)

    def test_stderr_open_failure_closes_stdout_and_preserves_generic_error(self):
        io, root = self.io()
        real_open = control.os.open

        def fail_stderr(path, *args):
            if Path(path).suffix == '.stderr':
                raise OSError('stderr open')
            return real_open(path, *args)

        with patch.object(control.os, 'open', side_effect=fail_stderr):
            with self.assertRaisesRegex(OSError, 'stderr open'):
                io.command(['command'])
        self.assertEqual(len(list(root.glob('*.stdout'))), 1)
        self.assertEqual(list(root.glob('*.stderr')), [])

    def test_systemd_timeout_stops_and_verifies_pinned_unit_once(self):
        io, root = self.io()
        process = _Process()
        process.communicate = lambda input=None, timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(['systemd-run'], timeout))
        verified = b'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n'
        stop = Mock(returncode=0)
        show = Mock(returncode=0, stdout=verified, stderr=b'')
        with patch.object(control.subprocess, 'Popen', return_value=process), \
             patch.object(control.subprocess, 'run', side_effect=[stop, show]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                io.command(['systemd-run', '--unit=hat-test.service'])
        self.assertEqual(run.call_count, 2)
        outcome = json.loads(next(root.glob('*.outcome.json')).read_text())
        self.assertFalse(outcome.get('cleanup_uncertain', False))
        self.assertEqual(outcome['cleanup']['verify'], 'inactive-dead-mainpid0')

    def test_systemd_cleanup_failure_is_durable_and_generic(self):
        io, root = self.io()
        process = _Process()
        process.communicate = lambda input=None, timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(['systemd-run', '--secret=value'], timeout))
        with patch.object(control.subprocess, 'Popen', return_value=process), \
             patch.object(control.subprocess, 'run', side_effect=PermissionError('EPERM')):
            with self.assertRaises(control.CommandCleanupUncertain) as caught:
                io.command(['systemd-run', '--unit=hat-test.service', '--secret=value'])
        self.assertNotIn('secret=value', str(caught.exception))
        artifact = next(root.glob('*.cleanup-uncertain.json'))
        value = json.loads(artifact.read_text())
        self.assertTrue(value['cleanup_uncertain'])
        self.assertNotIn('secret=value', artifact.read_text())

    def test_private_command_seams_are_present(self):
        self.assertTrue(hasattr(control.ControlIO, '_after_command_start'))
        self.assertTrue(hasattr(control.ControlIO, '_before_command_timeout'))

    def test_journal_root_fsync_failure_reopens_authoritative_schema(self):
        root = Path(tempfile.mkdtemp()).resolve()
        journal = control.Journal(root)
        journal._after_root_fsync = lambda label: (_ for _ in ()).throw(RuntimeError('root fsync'))
        with self.assertRaisesRegex(RuntimeError, 'root fsync'):
            journal.__enter__()
        with control.Journal(root) as reopened:
            self.assertEqual(control._journal_schema(reopened.db), control.RESTORE_CONTRACT)


if __name__ == '__main__':
    unittest.main()
