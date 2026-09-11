import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
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

if __name__ == '__main__': unittest.main()
