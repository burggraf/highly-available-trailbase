import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control

class ControllerBoundaryTests(unittest.TestCase):
    def test_copy_bound_input_rejects_symlink_and_preserves_bytes_mode(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root = Path(tmp)
            source = root / 'source'; source.write_bytes(b'raw\x00\xff\n')
            os.chmod(source, 0o600)
            dest = root / 'dest'
            identity = control.descriptor.stat_identity(source.stat())
            control._copy_bound_input(source, dest, 0o600, os.geteuid(), os.getegid(),
                                      hashlib.sha256(source.read_bytes()).hexdigest(), identity)
            self.assertEqual(dest.read_bytes(), b'raw\x00\xff\n')
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            link = root / 'link'; link.symlink_to(source)
            with self.assertRaises(ValueError):
                control._copy_bound_input(link, root / 'bad', 0o600, os.geteuid(), os.getegid(),
                                          hashlib.sha256(source.read_bytes()).hexdigest())

    def test_copy_bound_input_separates_sealed_source_owner_from_destination_owner(self):
        source_uid, source_gid = os.geteuid(), os.getegid()
        destination_uid, destination_gid = source_uid + 1000, source_gid + 1000
        identity = (11, 12, 0o100600, source_uid, source_gid, 1, 7)
        bound = MagicMock(identity=identity)
        parent = MagicMock()
        bound.__enter__.return_value = bound
        parent.__enter__.return_value = parent
        copied = MagicMock()
        bound.copy_to.return_value = copied
        with patch.object(control.descriptor.DescriptorAuthority, 'open_file', return_value=bound) as opened, \
             patch.object(control.descriptor.DescriptorAuthority, 'open_directory', return_value=parent):
            actual = control._copy_bound_input('/source', '/destination', 0o600,
                                               destination_uid, destination_gid, 'a' * 64, identity)
        self.assertEqual(actual, (11, 12, 0o600, source_uid, source_gid, 1, 7))
        self.assertEqual(opened.call_args.kwargs['expected_uid'], source_uid)
        self.assertEqual(opened.call_args.kwargs['expected_gid'], source_gid)
        bound.copy_to.assert_called_once_with(parent, 'destination', mode=0o600,
                                              uid=destination_uid, gid=destination_gid,
                                              fsync=None, label='copy')
        bound.recheck.assert_called_once_with()
        parent.recheck.assert_called_once_with()
        copied.close.assert_called_once_with()

    def test_copy_bound_input_refuses_wrong_sealed_source_identity(self):
        expected = (11, 12, 0o100600, os.geteuid(), os.getegid(), 1, 7)
        bound = MagicMock(identity=expected[:3] + (expected[3] + 1,) + expected[4:])
        parent = MagicMock()
        bound.__enter__.return_value = bound
        parent.__enter__.return_value = parent
        with patch.object(control.descriptor.DescriptorAuthority, 'open_file', return_value=bound), \
             patch.object(control.descriptor.DescriptorAuthority, 'open_directory', return_value=parent):
            with self.assertRaisesRegex(ValueError, 'source identity'):
                control._copy_bound_input('/source', '/destination', 0o600, 123, 456, 'a' * 64, expected)
        bound.copy_to.assert_not_called()

if __name__ == '__main__': unittest.main()
