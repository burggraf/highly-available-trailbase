import ast
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PATH = Path(__file__).with_name('restore_baseline.py')
spec = importlib.util.spec_from_file_location('restore_baseline_oracle', PATH)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class Response:
    status = 200

    def __init__(self, raw, status=200):
        self.raw, self.status = raw, status

    def read(self, limit=None):
        return self.raw if limit is None else self.raw[:limit]


class RestoreOracleTests(unittest.TestCase):
    def test_success_parser_is_strict_and_object_only(self):
        self.assertEqual(oracle._successful_object(b'{"id":1}'), {'id': 1})
        for raw in (b'{"id":1,"id":2}', b'[]', b'"text"', b'\xff'):
            with self.assertRaises(ValueError):
                oracle._successful_object(raw)

    def test_http_helper_returns_raw_and_rejects_oversize(self):
        with mock.patch.object(oracle.urllib.request, 'urlopen', return_value=Response(b'{"ok":1}')):
            self.assertEqual(oracle._http_request('http://x', '/health'), (200, b'{"ok":1}'))
        with mock.patch.object(oracle.urllib.request, 'urlopen', return_value=Response(b'x' * (oracle._HTTP_JSON_LIMIT + 1))):
            with self.assertRaises(ValueError):
                oracle._http_request('http://x', '/health')

    def test_auth_and_acknowledged_record_contract(self):
        rows = [
            {'auth_token': 'unused', 'retained_refresh': 'keep', 'revoked_refresh': 'gone'},
            {'event': 'acknowledged', 'api': 'main_ops', 'id': '7',
             'row': {'op_key': 'd1-op', 'payload': 'value'}},
        ]
        responses = iter(((400, b'bad'), (200, b'{"auth_token":"fresh","extra":true}'),
                          (200, b'{"id":7,"op_key":"d1-op","payload":"value","extra":1}')))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            ledger = Path(directory) / 'ledger'
            ledger.write_bytes(b'\n'.join(oracle.recovery.canonical_json(row) for row in rows))
            with mock.patch.object(oracle, '_http_request', side_effect=lambda *args, **kwargs: next(responses)):
                oracle._verify_records_and_auth('http://x', ledger)

    def test_source_has_no_demo_verify_import_or_assert(self):
        tree = ast.parse(PATH.read_text())
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertNotIn('demo_smoke', PATH.read_text())

    def test_signature_uses_normative_transition_and_rechecks_held_authorities(self):
        events = []

        class Authority:
            def recheck(self):
                events.append('recheck')

        expected = {'main': 'patched'}
        with mock.patch.object(oracle.transition, 'logical_signature',
                               side_effect=lambda root: events.append(('signature', root)) or expected):
            actual = oracle._signature_for_data(Path('/data'), [Authority(), Authority()])
        self.assertIs(actual, expected)
        self.assertEqual(events, ['recheck', 'recheck', ('signature', Path('/data')), 'recheck', 'recheck'])

    def test_main_has_one_constant_error_boundary(self):
        secret = 'secret-token-from-argv'
        with mock.patch.object(oracle, '_main', side_effect=ValueError(secret)), \
             mock.patch('sys.stderr') as stderr:
            self.assertNotEqual(oracle.main([secret]), 0)
        stderr.write.assert_called_once_with('FAIL: restore baseline failed\\n')
        self.assertNotIn(secret, str(stderr.write.call_args))

    def test_parser_errors_are_converted_to_constant_failure(self):
        with mock.patch('sys.stderr') as stderr:
            self.assertEqual(oracle.main(['--unknown', 'secret-body']), 1)
        stderr.write.assert_called_once_with('FAIL: restore baseline failed\\n')

    def test_success_emits_only_fixed_pass(self):
        with mock.patch.object(oracle, '_main', return_value=0), mock.patch('sys.stdout') as stdout:
            self.assertEqual(oracle.main([]), 0)
        stdout.write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
