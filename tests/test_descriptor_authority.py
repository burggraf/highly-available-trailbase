import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import descriptor


class DescriptorAuthorityTests(unittest.TestCase):
    def make_tree(self):
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        parent = root / 'parent'; parent.mkdir(mode=0o700)
        source = parent / 'source'; source.write_bytes(b'bound bytes')
        source.chmod(0o600)
        return root, parent, source

    def test_recheck_refuses_replaced_ancestor_and_source(self):
        root, parent, source = self.make_tree()
        authority = descriptor.DescriptorAuthority.open_file(
            source, trusted_root=root, trusted_uids={os.geteuid()}, expected_uid=os.geteuid(),
            expected_gid=os.getegid(), expected_mode=0o600, expected_nlink=1, limit=1024)
        with authority:
            moved = root / 'moved'; parent.rename(moved)
            parent.mkdir(mode=0o700); (parent / 'source').write_bytes(b'bound bytes')
            (parent / 'source').chmod(0o600)
            with self.assertRaises(ValueError): authority.recheck()

        root, _, source = self.make_tree()
        with descriptor.DescriptorAuthority.open_file(
                source, trusted_root=root, trusted_uids={os.geteuid()}, expected_uid=os.geteuid(),
                expected_gid=os.getegid(), expected_mode=0o600, expected_nlink=1, limit=1024) as authority:
            source.write_bytes(b'changed')
            with self.assertRaises(ValueError): authority.recheck()

    def test_exclusive_copy_is_descriptor_bound_and_reopened(self):
        root, _, source = self.make_tree()
        destination = root / 'destination'; destination.mkdir(mode=0o700)
        with descriptor.DescriptorAuthority.open_file(
                source, trusted_root=root, trusted_uids={os.geteuid()}, expected_uid=os.geteuid(),
                expected_gid=os.getegid(), expected_mode=0o600, expected_nlink=1, limit=1024) as source_authority, \
             descriptor.DescriptorAuthority.open_directory(
                destination, trusted_root=root, trusted_uids={os.geteuid()}) as destination_authority:
            copied = source_authority.copy_to(destination_authority, 'copy', mode=0o640,
                                              uid=os.geteuid(), gid=os.getegid())
            with copied:
                self.assertEqual(copied.sha256, hashlib.sha256(b'bound bytes').hexdigest())
                self.assertEqual(copied.read(), b'bound bytes')
                source_authority.recheck(); destination_authority.recheck(); copied.recheck()
            with self.assertRaises(FileExistsError):
                source_authority.copy_to(destination_authority, 'copy', mode=0o640,
                                         uid=os.geteuid(), gid=os.getegid())


if __name__ == '__main__': unittest.main()
