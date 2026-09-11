import importlib.util
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / 'hat'))

spec = importlib.util.spec_from_file_location('transition', Path(__file__).parents[1] / 'hat' / 'transition.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)


class RestoreEvidenceTests(unittest.TestCase):
    cut = {'main': 0x10, 'session': 0x20, 'aux': 0x30}

    def test_requires_labeled_matching_evidence(self):
        output = b'\n'.join(
            f'txid={v:016x} to_txid={v:016x} position={v}'.encode()
            for v in self.cut.values())
        self.assertIsNone(transition.validate_restore_evidence(output, self.cut))

    def test_rejects_empty_unrelated_mismatch_and_split_labels(self):
        for output in (b'', b'restore complete', b'txid=10 to_txid=10 position=99',
                       b'txid=10\nto_txid=10 position=10', b'10',
                       b'txid=10 to_txid=10 position=10 extra=10'):
            with self.assertRaisesRegex(RuntimeError, 'restore cut evidence unavailable'):
                transition.validate_restore_evidence(output, self.cut)

    def test_shared_parser_requires_exact_expected_records_and_bound(self):
        transition.validate_restore_positions(b'txid=10 to_txid=10 position=16', [0x10])
        for output, expected in ((b'txid=10 to_txid=10 position=16', [0x10, 0x20]),
                                 (b'txid=10 to_txid=10 position=16\n' * 2, [0x10]),
                                 (b'x' * (transition._RESTORE_OUTPUT_LIMIT + 1), [0x10])):
            with self.assertRaisesRegex(RuntimeError, 'restore cut evidence unavailable'):
                transition.validate_restore_positions(output, expected)


if __name__ == '__main__':
    unittest.main()
