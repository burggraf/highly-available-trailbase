import inspect
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import control

class Task34ContractTests(unittest.TestCase):
    def test_oracle_has_no_caller_acceptance_request(self):
        self.assertNotIn('acceptance_request', inspect.signature(control.ControlIO.oracle).parameters)

    def test_d2_ledger_name_is_ledger_jsonl(self):
        source = Path(control.__file__).read_text()
        self.assertIn("ledger = work/'ledger.jsonl'", source)
        self.assertNotIn("work/'client.jsonl'", source)
