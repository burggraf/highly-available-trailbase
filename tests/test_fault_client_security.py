"""Actual loopback HTTP and subprocess regressions for the D3 evidence producer."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from tests.test_fault_client import client

@contextmanager
def server(codes=None,redirect=False,disconnect=False,body=b'{"ids":["7"]}'):
    state={'requests':[], 'received':threading.Event(),'codes':list(codes or [201])}
    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            state['requests'].append((self.command,self.path,self.headers.get('Authorization')))
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            state['received'].set()
            if disconnect:self.close_connection=True;return
            code=state['codes'].pop(0) if len(state['codes'])>1 else state['codes'][0]
            self.send_response(302 if redirect else code)
            if redirect:self.send_header('Location','/trap')
            self.end_headers();self.wfile.write(body)
        do_POST=handle_request;do_GET=handle_request
        def log_message(self,*_):pass
    http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=http.serve_forever,kwargs={'poll_interval':.01});thread.start()
    try:yield 'http://127.0.0.1:'+str(http.server_port),state
    finally:http.shutdown();thread.join();http.server_close()

class ClientSecurity(unittest.TestCase):
    def token(self,root):
        p=root/'token.jsonl';p.write_text(json.dumps({'auth_token':'secret','retained_refresh':'retain','revoked_refresh':'revoke'})+'\n'+json.dumps({'event':'smoke_pass'})+'\n');p.chmod(0o600);return p

    def test_url_rejected_before_token_read_and_redirect_never_followed(self):
        for base in ('http://127.0.0.1:18080@external-host','http://@127.0.0.1:18080','http://127.0.0.1:18080?x=1',' http://127.0.0.1:18080'):
            with patch.object(client,'_token') as token,self.assertRaises(ValueError):client.produce('unused','unused','d1-source',base=base)
            token.assert_not_called()
        with server(redirect=True) as (base,state):
            status,_,_=client._http(base+'/record','POST',{},'secret')
            self.assertEqual(status,302);self.assertEqual(len(state['requests']),1)

    def test_private_first_auth_frame_and_no_directory_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();token=self.token(root)
            self.assertEqual(client._token(token),'secret')
            token.chmod(0o644)
            with self.assertRaises(ValueError):client._token(token)
            token.chmod(0o600);alias=root/'alias';alias.symlink_to(token)
            with self.assertRaises(ValueError):client._token(alias)
            token.write_text('{}\n'+json.dumps({'auth_token':'secret'})+'\n')
            with self.assertRaises(ValueError):client._token(token)
            public=root/'public';public.mkdir(mode=0o755);public.chmod(0o755)
            with self.assertRaises(ValueError):client._private_file(public/'out')
            self.assertEqual(public.stat().st_mode&0o777,0o755)
            private=root/'private';private.mkdir(mode=0o700);link=root/'link';link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):client._private_file(link/'private/out')
            self.assertFalse((private/'out').exists())

    def test_transport_and_500_are_uncertain_not_retried(self):
        for disconnected in (False,True):
            with self.subTest(disconnected=disconnected),tempfile.TemporaryDirectory() as tmp,server([500],disconnect=disconnected) as (base,state):
                root=Path(tmp).resolve();out=root/'out';client.produce(self.token(root),out,'d1-source',duration=.05,interval=.1,base=base)
                rows=client.read_closed_ledger(out,expected_epoch='d1-source')
                self.assertEqual([r['event'] for r in rows],['submitted','uncertain']);self.assertEqual(len(state['requests']),1)
                self.assertNotIn('secret',out.read_text())

    def test_success_with_invalid_record_id_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp,server(body=json.dumps({'ids':['9'*30]}).encode()) as (base,state):
            root=Path(tmp).resolve();out=root/'out';client.produce(self.token(root),out,'d1-source',duration=.05,interval=.1,base=base)
            self.assertEqual(client.read_closed_ledger(out,expected_epoch='d1-source')[-1]['event'],'uncertain')

    def test_observer_auth_semantics_monotonic_gap_and_proxy_bypass(self):
        with tempfile.TemporaryDirectory() as tmp,server([403,503,401,200]) as (base,state),server([500]) as (proxy,trap):
            out=Path(tmp).resolve()/'observer'
            with patch.dict(os.environ,{'http_proxy':proxy,'HTTP_PROXY':proxy,'no_proxy':'','NO_PROXY':''}),patch.object(client.time,'time_ns',side_effect=range(10000,0,-1)):
                client.observe(out,duration=.55,interval=.1,timeout=1,base=base)
            rows=[json.loads(line) for line in out.read_text().splitlines()];observations=[r for r in rows if r['event']=='observation']
            self.assertGreaterEqual(len(observations),4);self.assertTrue(observations[0]['available']);self.assertFalse(observations[-1]['available'])
            self.assertEqual(observations[-1]['availability'],'unexpected_anonymous_access')
            self.assertTrue(all(r['completed_ns']>=r['started_ns'] for r in observations))
            self.assertTrue(rows[-1]['observation_windows']);self.assertEqual(trap['requests'],[])
            self.assertTrue(all(method=='GET' and token is None for method,path,token in state['requests']))

    def test_sigterm_finishes_ledger_without_waiting_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp,server() as (base,state):
            root=Path(tmp).resolve();out=root/'out';token=self.token(root)
            p=subprocess.Popen([sys.executable,client.__file__,'produce','--token-ledger',str(token),'--output',str(out),'--source-epoch','d1-source','--duration','10','--interval','5','--base',base],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertTrue(state['received'].wait(3));p.terminate();stdout,stderr=p.communicate(timeout=2)
                self.assertEqual(p.returncode,0,stderr.decode());self.assertNotIn(b'secret',stdout+stderr)
                self.assertEqual(len(client.read_closed_ledger(out,expected_epoch='d1-source')),2)
            finally:
                if p.poll() is None:p.kill();p.communicate()

    def test_closed_ledger_requires_epoch_complete_matching_rows_and_types(self):
        row={'op_key':'d3-'+('b'*32),'payload':'value'}
        rows=[dict(event='start',run_id='d3-'+('a'*32),source_epoch='d1-source',time_ns=1,utc='2026-09-09T00:00:00Z'),dict(event='submitted',api='main_ops',row=row,time_ns=2),dict(event='acknowledged',api='main_ops',row=dict(row),id='7',time_ns=3),dict(event='stop',submitted=1,acknowledged=1,rejected=0,uncertain=0,time_ns=4,utc='2026-09-09T00:00:00Z')]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'ledger'
            def save(value):path.write_text(''.join(json.dumps(r)+'\n' for r in value));path.chmod(0o600)
            save(rows);self.assertEqual(len(client.read_closed_ledger(path,expected_epoch='d1-source')),2)
            with self.assertRaises(ValueError):client.read_closed_ledger(path,expected_epoch='d1-other')
            mutations=[]
            for bad_payload in (5,'x'*4097):
                altered=copy.deepcopy(rows);altered[1]['row']['payload']=bad_payload;mutations.append(altered)
            altered=copy.deepcopy(rows);altered[2]['row']['payload']='different';mutations.append(altered)
            altered=copy.deepcopy(rows);altered[0]=[];mutations.append(altered)
            altered=copy.deepcopy(rows);altered[1]['row']=None;mutations.append(altered)
            altered=copy.deepcopy(rows);altered.pop(2);altered[-1]['acknowledged']=0;mutations.append(altered)
            for altered in mutations:
                save(altered)
                with self.assertRaises(ValueError):client.read_closed_ledger(path,expected_epoch='d1-source')
            save(rows)
            with patch.object(client,'MAX_SUBMISSIONS',0),self.assertRaises(ValueError):client.read_closed_ledger(path,expected_epoch='d1-source')

if __name__=='__main__':unittest.main()
