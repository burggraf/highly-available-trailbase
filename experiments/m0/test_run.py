import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from run import OwnedProcess, require_private_run_root, require_stopped, stop_owned


class RunRootTests(unittest.TestCase):
    def test_rejects_existing_populated_root(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            (root / "existing").write_text("x")
            with self.assertRaises(ValueError):
                require_private_run_root(root, Path(parent) / "repo")

    def test_rejects_root_inside_repository(self):
        with tempfile.TemporaryDirectory() as parent:
            repo = Path(parent) / "repo"
            repo.mkdir()
            with self.assertRaises(ValueError):
                require_private_run_root(repo / "run", repo)


class ProcessOwnershipTests(unittest.TestCase):
    def test_only_owned_processes_are_stopped(self):
        process = subprocess.Popen(
            ["python3", "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        owned = OwnedProcess(process, "test")
        try:
            stop_owned([owned], timeout=2)
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_promotion_requires_all_children_stopped(self):
        live = mock.Mock(poll=mock.Mock(return_value=None))
        with self.assertRaises(RuntimeError):
            require_stopped([OwnedProcess(live, "follower")])

    def test_stopped_children_are_accepted(self):
        stopped = mock.Mock(poll=mock.Mock(return_value=0))
        require_stopped([OwnedProcess(stopped, "follower")])


if __name__ == "__main__":
    unittest.main()
