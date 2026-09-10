"""Local native-adapter unit contracts; no native processes or live endpoints."""
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.error

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import admission
try:
    import native_adapter
except ModuleNotFoundError:
    native_adapter = None


class Response:
    def __init__(self, status=201, body=b'{"ids":[1]}'):
        self.status, self.body = status, body
    def read(self, limit): return self.body
    def __enter__(self): return self
    def __exit__(self, *_): pass


class Opener:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response or Response(), error, []
    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error: raise self.error
        return self.response


class Result:
    def __init__(self, returncode=0, stdout=b'', stderr=b''):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class Runner:
    def __init__(self, row=('native-main_ops', 'must-survive'), sync=None, failure=None, hook=None):
        self.row, self.sync, self.failure, self.hook, self.calls = row, sync, failure, hook, []
    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.hook: self.hook(self, argv)
        if self.failure and len(self.calls) == self.failure[0]: raise self.failure[1]
        if argv[1] == 'sync':
            value = self.sync or {'db_path': argv[-1], 'txid': 2, 'replica_txid': 2, 'duration_ms': 1}
            return Result(stdout=json.dumps(value).encode())
        if argv[1] == 'restore':
            output = Path(argv[argv.index('-o') + 1])
            with closing(sqlite3.connect(output)) as db:
                db.execute('CREATE TABLE hat_ops(id INTEGER PRIMARY KEY, op_key TEXT, payload TEXT)')
                if self.row is not None: db.execute('INSERT INTO hat_ops VALUES(1,?,?)', self.row)
                db.commit()
            return Result(stdout=b'restored')
        raise AssertionError(argv)


class NativeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(native_adapter, 'missing local native adapter')
        self.tmp = tempfile.TemporaryDirectory(dir=HERE); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.root.chmod(0o700)
        self.binary = self.root / 'litestream'; self.binary.write_bytes(b'pinned binary'); self.binary.chmod(0o700)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.config = self.root / 'litestream.yml'; self.config.write_text('fixture'); self.config.chmod(0o600)
        self.dbs = {}
        for name in ('main', 'aux'):
            path = self.root / (name + '.db')
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE hat_ops(id INTEGER PRIMARY KEY, op_key TEXT, payload TEXT)'); db.commit()
            path.chmod(0o600); self.dbs[name] = path
        self.socket = self.root / 'control.sock'; self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.socket)); self.socket.chmod(0o600)
        self.addCleanup(self.listener.close)
        self.jroot = self.root / 'journal'; self.jroot.mkdir(mode=0o700)
        self.request = {'operation_id': 'a' * 32, 'method': 'POST',
            'path': '/api/records/v1/main_ops', 'body': b'{"op_key":"native-main_ops","payload":"must-survive"}',
            'headers': {'content-type':'application/json','authorization':'Bearer NEVER_STORE_TOKEN'},
            'epoch':'d1-local-adapter','writer_boot':'12345678-1234-1234-1234-123456789abc'}

    def adapter(self, opener=None, runner=None, **changes):
        values = dict(root=self.root, base_url='http://127.0.0.1:18081', litestream=self.binary,
                      binary_sha256=self.digest, socket_path=self.socket, config=self.config,
                      databases=self.dbs, opener=opener or Opener(), runner=runner or Runner())
        values.update(changes)
        return native_adapter.NativeAdapter(**values)

    def rows(self, journal):
        return journal.db.execute('SELECT operation,status,proof_evidence,txid FROM operations').fetchall()

    def test_main_create_forwards_once_syncs_once_restores_once_and_releases(self):
        opener, runner = Opener(), Runner()
        adapter = self.adapter(opener, runner)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision = native_adapter.admit_native(journal, self.request, adapter)
            rows = self.rows(journal)
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual([call[0][1] for call in runner.calls], ['sync', 'restore'])
        self.assertEqual(rows, [('a' * 32, 'proven', 'native-' + 'a' * 32 + '-main-2', 2)])
        self.assertEqual((decision.released, decision.status, decision.reason), (True, 201, 'proven'))
        evidence = self.root/'evidence'/('a'*32)
        proof = json.loads((evidence/'proof.json').read_text())
        self.assertEqual((proof['database'], proof['txid'], proof['membership']), ('main', 2, 'PASS'))
        self.assertEqual(stat.S_IMODE((evidence/'main.db').stat().st_mode), 0o600)

    def test_aux_create_selects_aux_database_and_exact_row(self):
        request = dict(self.request, operation_id='b'*32, path='/api/records/v1/aux_ops',
                       body=b'{"op_key":"native-aux_ops","payload":"must-survive"}')
        runner = Runner(row=('native-aux_ops','must-survive'))
        adapter = self.adapter(runner=runner)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision = native_adapter.admit_native(journal, request, adapter)
        self.assertTrue(decision.released)
        self.assertEqual(runner.calls[0][0][-1], str(self.dbs['aux']))

    def test_non_first_slice_paths_refuse_before_kernel_or_callbacks(self):
        invalid = [
            dict(self.request, path='/api/auth/v1/login'), dict(self.request, path='/api/auth/v1/logout'),
            dict(self.request, path='/api/auth/v1/refresh'), dict(self.request, path='/api/auth/v1/register'),
            dict(self.request, path='/api/records/v1/main_ops/1'),
            dict(self.request, path='/api/records/v1/main_ops?q=x'), dict(self.request, method='DELETE'),
        ]
        for index, request in enumerate(invalid):
            opener, runner = Opener(), Runner()
            request['operation_id'] = f'{index + 20:032x}'
            with self.subTest(path=request['path']), admission.AdmissionJournal(self.jroot) as journal:
                with self.assertRaisesRegex(ValueError, 'unsupported native adapter request'):
                    native_adapter.admit_native(journal, request, self.adapter(opener, runner))
                self.assertEqual((opener.calls, runner.calls, self.rows(journal)), ([], [], []))

    def test_configuration_requires_private_contained_paths_loopback_and_hash(self):
        outside = Path(self.tmp.name + '-outside')
        outside.write_text('x'); self.addCleanup(outside.unlink, missing_ok=True)
        cases = [
            {'base_url':'http://example.com:18081'}, {'base_url':'https://127.0.0.1:18081'},
            {'binary_sha256':'0'*64}, {'litestream':Path('/bin/echo')},
            {'config':outside}, {'socket_path':Path(str(outside) + '.sock')},
            {'databases':{'main':self.dbs['main']}},
        ]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.adapter(**changes)

    def test_subclass_may_require_a_different_exact_database_set(self):
        class SessionAdapter(native_adapter.NativeAdapter):
            DATABASES = {'session'}
        adapter = SessionAdapter(root=self.root, base_url='http://127.0.0.1:18081',
            litestream=self.binary, binary_sha256=self.digest, socket_path=self.socket,
            config=self.config, databases={'session':self.dbs['main']}, opener=Opener(), runner=Runner())
        self.assertEqual(set(adapter.databases), {'session'})
        with self.assertRaisesRegex(ValueError, 'databases differ'):
            SessionAdapter(root=self.root, base_url='http://127.0.0.1:18081',
                litestream=self.binary, binary_sha256=self.digest, socket_path=self.socket,
                config=self.config, databases=self.dbs, opener=Opener(), runner=Runner())

    def test_symlinked_binary_database_or_path_component_refuses(self):
        linked_binary = self.root / 'linked-litestream'; linked_binary.symlink_to(self.binary)
        linked_db = self.root / 'linked-main.db'; linked_db.symlink_to(self.dbs['main'])
        real = self.root/'real'; real.mkdir(); inner = real/'config'; inner.write_text('fixture'); inner.chmod(0o600)
        alias = self.root/'alias'; alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            self.adapter(litestream=linked_binary)
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            self.adapter(databases={'main':linked_db,'aux':self.dbs['aux']})
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            self.adapter(config=alias/'config')

    def test_database_replacement_after_validation_refuses_before_native_command(self):
        runner=Runner();adapter=self.adapter(runner=runner)
        old=self.dbs['main'];replacement=self.root/'replacement.db'
        replacement.write_bytes(old.read_bytes());replacement.chmod(0o600);os.replace(replacement,old)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision=native_adapter.admit_native(journal,self.request,adapter)
        self.assertEqual((decision.released,decision.reason,runner.calls),(False,'proof_uncertain',[]))

    def test_adapter_rechecks_complete_kernel_binding_before_native_command(self):
        runner=Runner();adapter=self.adapter(runner=runner)
        adapter.forward(self.request)
        requirement={'operation_id':'a'*32,'request_digest':'0'*64,'epoch':self.request['epoch'],
                     'writer_boot':self.request['writer_boot'],'database':'main'}
        with self.assertRaisesRegex(RuntimeError,'forward binding'):
            adapter.prove(requirement)
        self.assertEqual(runner.calls,[])

    def test_default_command_timeout_stops_descendant_process_group(self):
        marker=self.root/'child-stopped';pidfile=self.root/'child-pid'
        child=("import os,signal,sys,time; marker=sys.argv[1]; ready_fd=int(sys.argv[2]); "
               "signal.signal(signal.SIGTERM,lambda *_:(open(marker,'w').write('stopped'),sys.exit(0))); "
               "os.write(ready_fd,b'ready'); time.sleep(30)")
        parent=("import os,subprocess,sys,time; ready_read,ready_write=os.pipe(); "
                "p=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],str(ready_write)], "
                "pass_fds=(ready_write,)); os.close(ready_write); "
                "assert os.read(ready_read,len(b'ready')) == b'ready'; os.close(ready_read); "
                "pending=sys.argv[3]+'.pending'; open(pending,'w').write(str(p.pid)); "
                "os.replace(pending,sys.argv[3]); time.sleep(30)")
        with self.assertRaises(subprocess.TimeoutExpired):
            native_adapter._run_group([sys.executable,'-c',parent,child,str(marker),str(pidfile)],
                                      {'PATH':os.environ.get('PATH','/usr/bin:/bin')},2)
        self.assertTrue(pidfile.is_file())
        self.assertTrue(marker.is_file())
        child_pid=int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError): os.kill(child_pid,0)

    def test_intermediate_symlink_in_root_refuses(self):
        actual=self.root/'actual-root';actual.mkdir(mode=0o700)
        alias=self.root/'parent-alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'root.*symlinked'):
            self.adapter(root=alias/'actual-root')

    def test_symlink_then_parent_traversal_in_root_refuses_before_normalization(self):
        actual=self.root/'actual-root';actual.mkdir(mode=0o700)
        target=self.root/'target';target.mkdir(mode=0o700)
        link=self.root/'link';link.symlink_to(target,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'root.*parent traversal'):
            self.adapter(root=link/'..'/'actual-root')

    def test_operation_directory_replacement_refuses_before_output_publication(self):
        def replace(_,argv):
            if argv[1]=='sync':
                directory=self.root/'evidence'/('a'*32)
                directory.rename(self.root/'moved-operation')
                directory.mkdir(mode=0o700)
        runner=Runner(hook=replace);adapter=self.adapter(runner=runner)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision=native_adapter.admit_native(journal,self.request,adapter)
        self.assertEqual((decision.released,decision.reason,len(runner.calls)),(False,'proof_uncertain',1))
        self.assertTrue((self.root/'moved-operation'/'sync.intent.json').is_file())
        self.assertFalse((self.root/'evidence'/('a'*32)/'proof.json').exists())

    def test_native_command_output_limit_terminates_and_refuses(self):
        command=[sys.executable,'-c',f"import os;os.write(1,b'x'*({1024*1024}+1))"]
        with self.assertRaises(native_adapter.CommandOutputLimit) as caught:
            native_adapter._run_group(command,{'PATH':os.environ.get('PATH','/usr/bin:/bin')},5)
        self.assertLessEqual(len(caught.exception.stdout),1024*1024)

    def test_transport_error_is_durable_forward_uncertain_and_never_replays(self):
        opener, runner = Opener(error=OSError('NEVER_LEAK_TRANSPORT')), Runner()
        adapter = self.adapter(opener, runner)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision = native_adapter.admit_native(journal, self.request, adapter)
        with admission.AdmissionJournal(self.jroot) as journal:
            self.assertEqual(self.rows(journal), [('a'*32, 'forward_uncertain', None, None)])
            with self.assertRaisesRegex(RuntimeError, 'operation identity already used'):
                native_adapter.admit_native(journal, self.request, adapter)
        self.assertEqual((decision.released, decision.reason, decision.body),
                         (False, 'forward_uncertain', b'admission forward uncertain'))
        self.assertEqual((len(opener.calls), runner.calls), (1, []))
        self.assertFalse((self.root/'evidence'/('a'*32)).exists())

    def test_http_error_is_possible_and_requires_proof(self):
        opener, runner = Opener(Response(403,b'NEVER_RELEASE_4XX')), Runner(failure=(1,RuntimeError('proof unavailable')))
        with admission.AdmissionJournal(self.jroot) as journal:
            decision = native_adapter.admit_native(journal, self.request, self.adapter(opener, runner))
            self.assertEqual(self.rows(journal)[0][1], 'proof_uncertain')
        self.assertEqual((decision.released, decision.status, decision.reason), (False, 503, 'proof_uncertain'))
        self.assertNotIn(b'NEVER_RELEASE_4XX', decision.body)

    def test_malformed_sync_or_response_and_missing_row_refuse_without_retry(self):
        scenarios = [
            (Opener(Response(201,b'{}')), Runner()),
            (Opener(), Runner(sync={'db_path':str(self.dbs['main']),'txid':2,'replica_txid':1,'duration_ms':1})),
            (Opener(), Runner(row=None)),
            (Opener(), Runner(row=('wrong','must-survive'))),
        ]
        for index, (opener, runner) in enumerate(scenarios):
            request = dict(self.request, operation_id=f'{index + 50:032x}')
            with self.subTest(index=index), admission.AdmissionJournal(self.jroot) as journal:
                decision = native_adapter.admit_native(journal, request, self.adapter(opener, runner))
                self.assertEqual(self.rows(journal)[0][1], 'proof_uncertain')
            self.assertFalse(decision.released)
            self.assertLessEqual(len(opener.calls), 1)
            self.assertLessEqual(len([c for c in runner.calls if c[0][1]=='sync']), 1)
            self.assertLessEqual(len([c for c in runner.calls if c[0][1]=='restore']), 1)

    def test_native_timeout_is_durable_proof_uncertain_and_never_replays(self):
        error=subprocess.TimeoutExpired(['litestream','sync'],10,output=b'partial',stderr=b'timeout')
        opener=Opener();runner=Runner(failure=(1,error));adapter=self.adapter(opener,runner)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision=native_adapter.admit_native(journal,self.request,adapter)
        with admission.AdmissionJournal(self.jroot) as journal:
            self.assertEqual(self.rows(journal), [('a'*32, 'proof_uncertain', None, None)])
            with self.assertRaisesRegex(RuntimeError, 'operation identity already used'):
                native_adapter.admit_native(journal,self.request,adapter)
        self.assertEqual((decision.released,decision.reason,len(runner.calls)),(False,'proof_uncertain',1))
        self.assertEqual(len(opener.calls), 1)
        evidence=self.root/'evidence'/('a'*32)
        self.assertTrue((evidence/'sync.intent.json').is_file())
        self.assertEqual(json.loads((evidence/'sync.outcome.json').read_text())['outcome'],'timeout')
        self.assertEqual((evidence/'sync.stdout').read_bytes(),b'partial')
        self.assertFalse((evidence/'restore.intent.json').exists())
        self.assertFalse((evidence/'proof.json').exists())

    def test_no_secret_or_body_is_persisted_by_adapter_or_journal(self):
        adapter=self.adapter(runner=Runner(failure=(1,RuntimeError('NEVER_STORE_EXCEPTION'))))
        with admission.AdmissionJournal(self.jroot) as journal:
            decision=native_adapter.admit_native(journal,self.request,adapter)
        metadata=b''.join(p.read_bytes() for p in self.root.rglob('*')
                          if p.is_file() and p.suffix not in ('.db', '') and p.name!='litestream')
        journal=(self.jroot/'journal.db').read_bytes()
        for secret in (b'NEVER_STORE_TOKEN',b'must-survive',b'NEVER_STORE_EXCEPTION'):
            self.assertNotIn(secret,metadata+journal+decision.body)


if __name__=='__main__': unittest.main()
