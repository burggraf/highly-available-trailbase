import ast
import inspect
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control

class Task34ContractTests(unittest.TestCase):
    def test_oracle_has_no_caller_acceptance_request_or_source_epoch(self):
        parameters = inspect.signature(control.ControlIO.oracle).parameters
        self.assertNotIn('acceptance_request', parameters)
        self.assertNotIn('source_epoch', parameters)

    def test_remote_has_no_caller_epoch_and_calls_cannot_inject_one(self):
        self.assertNotIn('epoch', inspect.signature(control.ControlIO.remote).parameters)
        for source_path in (Path(control.__file__), Path(__file__).with_name('test_recover_driver.py'),
                            Path(__file__).with_name('test_rejoin_driver.py'),
                            Path(__file__).with_name('test_rejoin_boot_reconciliation.py')):
            tree = ast.parse(source_path.read_text())
            offenders = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute) and node.func.attr == 'remote'
                         and any(keyword.arg == 'epoch' for keyword in node.keywords)]
            self.assertEqual(offenders, [], f'{source_path}: caller-controlled epoch at {offenders}')

    def test_d2_ledger_name_is_ledger_jsonl(self):
        source = Path(control.__file__).read_text()
        self.assertIn("ledger = work/'ledger.jsonl'", source)
        self.assertNotIn("work/'client.jsonl'", source)

if __name__ == '__main__': unittest.main()
