"""Bounded local protocol-kernel tests; no live services or deployment inputs."""
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import admission
except ModuleNotFoundError:
    admission = None


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(admission, 'missing local admission prototype')
        self.tmp = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'journal'
        self.root.mkdir(mode=0o700)
        self.request = {
            'operation_id': '1' * 32,
            'method': 'POST',
            'path': '/api/records/v1/main_ops',
            'body': b'{"payload":"NEVER_STORE_BODY"}',
            'headers': {'content-type': 'application/json',
                        'authorization': 'Bearer NEVER_STORE_AUTH',
                        'cookie': 'NEVER_STORE_COOKIE'},
            'epoch': 'd1-local-prototype',
            'writer_boot': '12345678-1234-1234-1234-123456789abc',
        }

    def proof(self, requirement, **changes):
        value = dict(operation_id=requirement['operation_id'], request_digest=requirement['request_digest'],
                     epoch=requirement['epoch'], writer_boot=requirement['writer_boot'],
                     database=requirement['database'], txid=2, replica_txid=2,
                     image_verified=True, evidence_id='local-proof-2')
        value.update(changes)
        return value

    def rows(self, journal):
        return journal.db.execute('SELECT operation,status,upstream_status,proof_evidence,txid FROM operations').fetchall()

    def test_success_commits_intent_then_forward_then_proof_before_release(self):
        observed = []
        with admission.AdmissionJournal(self.root) as journal:
            def forward(request):
                observed.append(self.rows(journal))
                return {'status': 201, 'response_body': b'{"ids":[1]}', 'mutation': 'completed'}
            def prove(requirement):
                observed.append(self.rows(journal))
                return self.proof(requirement)
            decision = admission.admit(journal, self.request, forward, prove)
            final = self.rows(journal)
        self.assertEqual(observed[0][0][1], 'intent')
        self.assertEqual(observed[1][0][1], 'awaiting_proof')
        self.assertEqual(final, [('1' * 32, 'proven', 201, 'local-proof-2', 2)])
        self.assertTrue(decision.released)
        self.assertEqual((decision.status, decision.body, decision.reason), (201, b'{"ids":[1]}', 'proven'))

    def test_supported_surface_maps_exact_database(self):
        cases = {
            '/api/records/v1/main_ops': 'main', '/api/records/v1/aux_ops': 'aux',
            '/api/auth/v1/login': 'session', '/api/auth/v1/logout': 'session',
            '/api/auth/v1/refresh': 'session',
        }
        for index, (path, database) in enumerate(cases.items(), 1):
            with self.subTest(path=path), admission.AdmissionJournal(self.root) as journal:
                request = dict(self.request, operation_id=f'{index + 10:032x}', path=path)
                seen = []
                decision = admission.admit(journal, request,
                    lambda _: {'status': 200, 'response_body': b'{}', 'mutation': 'completed'},
                    lambda requirement: seen.append(requirement) or self.proof(requirement))
                self.assertTrue(decision.released)
                self.assertEqual(seen[0]['database'], database)

    def test_unsupported_or_malformed_request_has_no_journal_or_callbacks(self):
        invalid = [
            dict(self.request, method='PATCH'), dict(self.request, path='/api/records/v1/main_ops/1'),
            dict(self.request, path='/api/auth/v1/register'), dict(self.request, path='/api/records/v1/main_ops?q=x'),
            dict(self.request, operation_id='A' * 32), dict(self.request, epoch='wrong'),
            dict(self.request, writer_boot='wrong'), dict(self.request, body='not-bytes'),
            dict(self.request, body=b'x' * (1024 * 1024 + 1)),
            dict(self.request, headers={'x-forwarded-for': 'secret'}),
            self.request | {'extra': True},
        ]
        for value in invalid:
            called = []
            with self.subTest(value=value), admission.AdmissionJournal(self.root) as journal:
                with self.assertRaisesRegex(ValueError, 'invalid admission request'):
                    admission.admit(journal, value, lambda _: called.append('forward'), lambda _: called.append('proof'))
                self.assertEqual(called, [])
                self.assertEqual(self.rows(journal), [])

    def test_proof_failures_never_release_upstream_success_or_body(self):
        changes = [
            {'operation_id': '2' * 32}, {'request_digest': '0' * 64}, {'epoch': 'd1-other'},
            {'writer_boot': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}, {'database': 'aux'},
            {'txid': 1, 'replica_txid': 2}, {'txid': 0, 'replica_txid': 0},
            {'image_verified': False}, {'evidence_id': '../bad'}, {'extra': True},
        ]
        for index, change in enumerate(changes, 1):
            with self.subTest(change=change), admission.AdmissionJournal(self.root) as journal:
                request = dict(self.request, operation_id=f'{index + 100:032x}')
                decision = admission.admit(journal, request,
                    lambda _: {'status': 201, 'response_body': b'NEVER_RELEASE_SUCCESS', 'mutation': 'completed'},
                    lambda requirement, change=change: self.proof(requirement, **change))
                self.assertFalse(decision.released)
                self.assertEqual((decision.status, decision.body, decision.reason),
                                 (503, b'admission proof uncertain', 'proof_uncertain'))
                self.assertEqual(self.rows(journal)[-1][1], 'proof_uncertain')

    def test_forward_cannot_mutate_the_committed_proof_binding(self):
        expected = dict(self.request)
        expected['headers'] = dict(self.request['headers'])
        seen = []
        with admission.AdmissionJournal(self.root) as journal:
            def forward(request):
                request['epoch'] = 'd1-mutated'
                request['writer_boot'] = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                request['headers']['authorization'] = 'Bearer mutated'
                request['body'] = b'mutated'
                return {'status': 201, 'response_body': b'{}', 'mutation': 'completed'}
            decision = admission.admit(journal, self.request, forward,
                lambda requirement: seen.append(requirement) or self.proof(requirement))
        self.assertTrue(decision.released)
        self.assertEqual(self.request, expected)
        self.assertEqual(seen[0]['epoch'], expected['epoch'])
        self.assertEqual(seen[0]['writer_boot'], expected['writer_boot'])

    def test_callback_exceptions_and_possible_error_remain_uncertain(self):
        with admission.AdmissionJournal(self.root) as journal:
            decision = admission.admit(journal, self.request,
                lambda _: (_ for _ in ()).throw(RuntimeError('NEVER_LEAK_FORWARD')),
                lambda _: self.fail('proof called'))
            self.assertEqual((decision.released, decision.reason), (False, 'forward_uncertain'))
            self.assertEqual(self.rows(journal)[0][1], 'forward_uncertain')
        with admission.AdmissionJournal(self.root) as journal:
            request = dict(self.request, operation_id='2' * 32)
            decision = admission.admit(journal, request,
                lambda _: {'status': 500, 'response_body': b'NEVER_RELEASE_ERROR', 'mutation': 'possible'},
                lambda _: (_ for _ in ()).throw(RuntimeError('NEVER_LEAK_PROOF')))
            self.assertEqual((decision.released, decision.status, decision.reason), (False, 503, 'proof_uncertain'))
            self.assertNotIn(b'NEVER_RELEASE', decision.body)

    def test_caller_cannot_assert_non_mutation_or_release_a_4xx_without_proof(self):
        calls = []
        with admission.AdmissionJournal(self.root) as journal:
            decision = admission.admit(journal, self.request,
                lambda _: calls.append('forward') or {'status': 403, 'response_body': b'{"error":"denied"}', 'mutation': 'none'},
                lambda _: calls.append('proof'))
            self.assertEqual(calls, ['forward'])
            self.assertEqual(self.rows(journal)[0][1], 'forward_uncertain')
        self.assertEqual((decision.released, decision.status, decision.body, decision.reason),
                         (False, 503, b'admission forward uncertain', 'forward_uncertain'))

    def test_duplicate_operation_never_calls_callbacks_or_changes_rows(self):
        with admission.AdmissionJournal(self.root) as journal:
            first = admission.admit(journal, self.request,
                lambda _: {'status': 201, 'response_body': b'created', 'mutation': 'completed'},
                lambda requirement: self.proof(requirement))
            before = self.rows(journal)
            for body in (self.request['body'], b'different'):
                called = []
                with self.assertRaisesRegex(RuntimeError, 'operation identity already used'):
                    admission.admit(journal, dict(self.request, body=body),
                                    lambda _: called.append('forward'), lambda _: called.append('proof'))
                self.assertEqual(called, [])
                self.assertEqual(self.rows(journal), before)
        self.assertTrue(first.released)

    def test_process_death_after_intent_is_durable_and_never_reopened(self):
        helper = HERE / 'death_helper.py'
        helper.write_text("""import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]);import admission
request={'operation_id':'3'*32,'method':'POST','path':'/api/records/v1/main_ops','body':b'body','headers':{'content-type':'application/json'},'epoch':'d1-local-prototype','writer_boot':'12345678-1234-1234-1234-123456789abc'}
with admission.AdmissionJournal(Path(sys.argv[2])) as journal:
 admission.admit(journal,request,lambda _:(os.write(1,b'INTENT OBSERVED\\n'),os._exit(17)),lambda _:None)
""")
        self.addCleanup(lambda: helper.unlink(missing_ok=True))
        result = subprocess.run([sys.executable, '-I', '-B', str(helper), str(HERE), str(self.root)],
                                capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout), (17, b'INTENT OBSERVED\n'))
        request = dict(self.request, operation_id='3' * 32)
        with admission.AdmissionJournal(self.root) as journal:
            self.assertEqual(self.rows(journal)[0][1], 'intent')
            before = self.rows(journal)
            with self.assertRaisesRegex(RuntimeError, 'operation identity already used'):
                admission.admit(journal, request, self.fail, self.fail)
            self.assertEqual(self.rows(journal), before)

    def test_existing_sqlite_sidecar_symlink_refuses(self):
        with admission.AdmissionJournal(self.root):
            pass
        outside = self.root.parent / 'outside'
        outside.write_bytes(b'not journal data')
        (self.root / 'journal.db-wal').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'admission journal file must be private'):
            with admission.AdmissionJournal(self.root):
                pass

    def test_authority_lock_and_database_replacement_refuse(self):
        first = admission.AdmissionJournal(self.root)
        first.__enter__(); self.addCleanup(first.__exit__, None, None, None)
        with self.assertRaises(BlockingIOError):
            with admission.AdmissionJournal(self.root): pass
        old = self.root / 'journal.db'; replacement = self.root / 'replacement'
        replacement.write_bytes(old.read_bytes()); replacement.chmod(0o600); os.replace(replacement, old)
        with self.assertRaisesRegex(RuntimeError, 'journal authority lost'):
            admission.admit(first, self.request, self.fail, self.fail)

    def test_journal_and_errors_do_not_contain_secrets_or_bodies(self):
        with admission.AdmissionJournal(self.root) as journal:
            decision = admission.admit(journal, self.request,
                lambda _: {'status': 500, 'response_body': b'NEVER_STORE_RESPONSE', 'mutation': 'possible'},
                lambda _: (_ for _ in ()).throw(RuntimeError('NEVER_STORE_EXCEPTION')))
        raw = (self.root / 'journal.db').read_bytes()
        for secret in (b'NEVER_STORE_BODY', b'NEVER_STORE_AUTH', b'NEVER_STORE_COOKIE',
                       b'NEVER_STORE_RESPONSE', b'NEVER_STORE_EXCEPTION'):
            self.assertNotIn(secret, raw + decision.body + decision.reason.encode())

    def test_actual_kernel_stays_inside_journal_root_under_audit_hook(self):
        helper = r'''
import os,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]);import admission
root=Path(sys.argv[2]).resolve()
def deny(event,args):
 if event.startswith('socket.') or event.startswith('subprocess.') or event in ('os.system','os.exec','os.fork','os.forkpty','os.posix_spawn'):
  raise RuntimeError('operational capability blocked')
 if event=='open' and isinstance(args[0],(str,bytes)):
  path=Path(os.fsdecode(args[0])).resolve()
  if path!=root and root not in path.parents: raise RuntimeError('outside file blocked')
sys.addaudithook(deny)
request={'operation_id':'4'*32,'method':'POST','path':'/api/records/v1/main_ops','body':b'body','headers':{'content-type':'application/json'},'epoch':'d1-local-prototype','writer_boot':'12345678-1234-1234-1234-123456789abc'}
with admission.AdmissionJournal(root) as journal:
 decision=admission.admit(journal,request,lambda _:(_ for _ in ()).throw(RuntimeError('fixture refusal')),lambda _:None)
assert not decision.released and decision.reason=='forward_uncertain'
for probe in (lambda:socket.socket(),lambda:open(root.parent/'must-not-create','w')):
 try:probe()
 except RuntimeError:pass
 else:raise AssertionError('audit negative control failed')
os.write(1,b'PASS\n')
'''
        process = subprocess.run([sys.executable, '-I', '-B', '-c', helper, str(HERE), str(self.root)],
                                 capture_output=True, timeout=5)
        self.assertEqual((process.returncode, process.stdout), (0, b'PASS\n'), process.stderr.decode())

    def test_module_has_no_operational_imports(self):
        source = (HERE / 'admission.py').read_text()
        for forbidden in ('subprocess', 'socket', 'urllib', 'requests', 'http.client'):
            self.assertNotIn('import ' + forbidden, source)


if __name__ == '__main__':
    unittest.main()
