"""Logout-only native transition proof contracts; no native processes or live endpoints."""
from contextlib import closing
import hashlib,json,os
from pathlib import Path
import socket,sqlite3,subprocess,sys,tempfile,unittest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import admission,native_adapter
try: import auth_logout_adapter
except ModuleNotFoundError: auth_logout_adapter=None

TOKEN='A'*86

class Response:
    def __init__(self,status=200,body=b''):self.status=status;self.body=body
    def read(self,limit): return self.body
    def __enter__(self): return self
    def __exit__(self,*_): pass

class Opener:
    def __init__(self,events,error=None,hook=None,response=None): self.events=events;self.error=error;self.hook=hook;self.response=response or Response();self.calls=[]
    def open(self,request,timeout):
        self.calls.append((request,timeout));self.events.append('http')
        if self.hook:self.hook()
        if self.error:raise self.error
        return self.response

class Result:
    def __init__(self,stdout=b'',returncode=0,stderr=b''):self.stdout=stdout;self.returncode=returncode;self.stderr=stderr

class Runner:
    def __init__(self,events,pre=True,post=False,txids=(1,2),failure=None,wal=False):
        self.events=events;self.pre=pre;self.post=post;self.txids=txids;self.failure=failure;self.wal=wal;self.calls=[];self.syncs=0
    def __call__(self,argv,**kwargs):
        self.calls.append((list(argv),kwargs));kind=argv[1];self.events.append(kind)
        if self.failure and len(self.calls)==self.failure[0]:raise self.failure[1]
        if kind=='sync':
            txid=self.txids[self.syncs];self.syncs+=1
            return Result(json.dumps({'db_path':argv[-1],'txid':txid,'replica_txid':txid,'duration_ms':1}).encode())
        if kind=='restore':
            output=Path(argv[argv.index('-o')+1]);present=self.pre if 'predecessor' in output.name else self.post
            with closing(sqlite3.connect(output)) as db:
                if self.wal:self.assert_wal(db)
                db.execute('CREATE TABLE _session(id INTEGER PRIMARY KEY,user BLOB NOT NULL,refresh_token TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL) STRICT')
                if present:db.execute('INSERT INTO _session VALUES(1,?,?,?,?)',(b'1'*16,TOKEN,1,4102444800))
                db.commit()
            output.chmod(0o600);return Result(b'restored')
        raise AssertionError(argv)
    def assert_wal(self,db):
        if db.execute('PRAGMA journal_mode=WAL').fetchone()!=('wal',):raise AssertionError('WAL unavailable')

class AuthLogoutAdapterTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(auth_logout_adapter,'missing logout adapter')
        self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.binary=self.root/'litestream';self.binary.write_bytes(b'pinned');self.binary.chmod(0o700)
        self.digest=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.config=self.root/'litestream.yml';self.config.write_text('fixture');self.config.chmod(0o600)
        self.session=self.root/'session.db'
        with closing(sqlite3.connect(self.session)) as db:db.execute('CREATE TABLE fixture(x)');db.commit()
        self.session.chmod(0o600)
        self.socket=self.root/'sync.sock';self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(self.socket));self.socket.chmod(0o600);self.addCleanup(self.listener.close)
        self.jroot=self.root/'journal';self.jroot.mkdir(mode=0o700)
        self.request={'operation_id':'a'*32,'method':'POST','path':'/api/auth/v1/logout',
            'body':json.dumps({'refresh_token':TOKEN},separators=(',',':')).encode(),
            'headers':{'content-type':'application/json'},'epoch':'d1-local-auth-logout',
            'writer_boot':'12345678-1234-1234-1234-123456789abc'}
    def adapter(self,opener,runner):
        return auth_logout_adapter.AuthLogoutAdapter(root=self.root,base_url='http://127.0.0.1:18081',
            litestream=self.binary,binary_sha256=self.digest,socket_path=self.socket,config=self.config,
            databases={'session':self.session},opener=opener,runner=runner)
    def row(self,journal):
        return journal.db.execute('SELECT status,upstream_status,proof_evidence,txid FROM operations').fetchone()
    def test_presence_to_newer_absence_forwards_once_and_releases(self):
        events=[];runner=Runner(events);holder={}
        opener=Opener(events,hook=lambda:self.assertEqual(self.row(holder['journal'])[0],'intent'))
        with admission.AdmissionJournal(self.jroot) as journal:
            holder['journal']=journal;decision=auth_logout_adapter.admit_logout(journal,self.request,self.adapter(opener,runner));row=self.row(journal)
        self.assertEqual(events,['sync','restore','http','sync','restore'])
        self.assertEqual((len(opener.calls),decision.released,decision.status,decision.body,decision.reason),(1,True,200,b'','proven'))
        self.assertEqual(row,('proven',200,'logout-'+'a'*32+'-session-1-2',2))
        proof=json.loads((self.root/'evidence'/('a'*32)/'proof.json').read_text())
        self.assertEqual((proof['predecessor_txid'],proof['txid'],proof['transition']),(1,2,'PRESENT_TO_ABSENT'))
        self.assertNotIn(TOKEN,(self.root/'evidence'/('a'*32)/'proof.json').read_text())
    def test_only_exact_post_logout_token_body_is_allowed_before_effects(self):
        invalid=[dict(self.request,path='/api/auth/v1/login'),dict(self.request,path='/api/auth/v1/refresh'),
            dict(self.request,path='/api/auth/v1/logout?x=1'),dict(self.request,method='GET'),
            dict(self.request,body=b'{}'),dict(self.request,body=json.dumps({'refresh_token':'A'*85}).encode()),
            dict(self.request,body=json.dumps({'refresh_token':'!'*86}).encode()),
            dict(self.request,body=json.dumps({'refresh_token':TOKEN,'extra':1}).encode()),
            dict(self.request,headers={'content-type':'application/json','cookie':'refresh_token=x'})]
        for index,request in enumerate(invalid):
            events=[];request['operation_id']=f'{index+20:032x}';opener=Opener(events);runner=Runner(events)
            with self.subTest(index=index),admission.AdmissionJournal(self.jroot) as journal:
                with self.assertRaisesRegex(ValueError,'unsupported logout request'):auth_logout_adapter.admit_logout(journal,request,self.adapter(opener,runner))
                self.assertEqual((events,journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]),([],0))
    def test_absent_predecessor_refuses_before_http_and_is_single_use(self):
        events=[];opener=Opener(events);runner=Runner(events,pre=False);adapter=self.adapter(opener,runner)
        with admission.AdmissionJournal(self.jroot) as journal:decision=auth_logout_adapter.admit_logout(journal,self.request,adapter)
        with admission.AdmissionJournal(self.jroot) as journal:
            self.assertEqual(self.row(journal)[0],'forward_uncertain')
            with self.assertRaisesRegex(RuntimeError,'operation identity already used'):auth_logout_adapter.admit_logout(journal,self.request,adapter)
        self.assertEqual((decision.released,decision.reason,events,len(opener.calls)),(False,'forward_uncertain',['sync','restore'],0))
    def test_successor_presence_or_nonincreasing_txid_is_proof_uncertain(self):
        for index,(post,txids) in enumerate(((True,(1,2)),(False,(2,2)),(False,(3,2)))):
            root=self.root/(f'case-{index}');root.mkdir(mode=0o700)
            # Reuse a fresh test instance's root contract by changing only journal/operation while adapter evidence stays unique.
            request=dict(self.request,operation_id=f'{index+40:032x}');journal_root=root/'journal';journal_root.mkdir(mode=0o700)
            events=[];opener=Opener(events);runner=Runner(events,post=post,txids=txids)
            with admission.AdmissionJournal(journal_root) as journal:decision=auth_logout_adapter.admit_logout(journal,request,self.adapter(opener,runner))
            self.assertEqual((decision.released,decision.reason),(False,'proof_uncertain'))
            self.assertEqual(len(opener.calls),1)
    def test_only_exact_empty_http_200_can_be_released(self):
        for index,response in enumerate((Response(201),Response(200,b'unexpected'))):
            request=dict(self.request,operation_id=f'{index+60:032x}');root=self.root/f'http-{index}';root.mkdir(mode=0o700)
            events=[];opener=Opener(events,response=response);runner=Runner(events)
            with admission.AdmissionJournal(root) as journal:decision=auth_logout_adapter.admit_logout(journal,request,self.adapter(opener,runner))
            self.assertEqual((decision.released,decision.reason),(False,'proof_uncertain'))

    def test_transport_loss_after_predecessor_is_forward_uncertain_without_post_sync(self):
        events=[];opener=Opener(events,error=OSError('SECRET_EXCEPTION'));runner=Runner(events)
        with admission.AdmissionJournal(self.jroot) as journal:decision=auth_logout_adapter.admit_logout(journal,self.request,self.adapter(opener,runner))
        self.assertEqual((decision.released,decision.reason,events),(False,'forward_uncertain',['sync','restore','http']))
    def test_wal_mode_restored_image_is_consumed_through_stable_descriptor(self):
        events=[];runner=Runner(events,wal=True);opener=Opener(events)
        with admission.AdmissionJournal(self.jroot) as journal:
            decision=auth_logout_adapter.admit_logout(journal,self.request,self.adapter(opener,runner))
        self.assertEqual((decision.released,decision.reason),(True,'proven'))

    def test_restored_image_replacement_cannot_change_consumed_membership(self):
        events=[];adapter=self.adapter(Opener(events),Runner(events))
        directory=adapter._directory('f'*32)
        _,image,identity=adapter._sync_restore(directory,'predecessor')
        replacement=directory/'replacement.db'
        with closing(sqlite3.connect(replacement)) as db:
            db.execute('CREATE TABLE _session(id INTEGER PRIMARY KEY,user BLOB NOT NULL,refresh_token TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL) STRICT');db.commit()
        replacement.chmod(0o600);os.replace(replacement,image)
        with self.assertRaisesRegex(RuntimeError,'image identity changed'):
            adapter._presence(image,TOKEN,identity)

    def test_binding_mismatch_refuses_before_successor_commands(self):
        events=[];adapter=self.adapter(Opener(events),Runner(events));adapter.forward(self.request)
        digest,database=admission._request(self.request)
        requirement={'operation_id':'a'*32,'request_digest':'0'*64,'epoch':self.request['epoch'],'writer_boot':self.request['writer_boot'],'database':database}
        with self.assertRaisesRegex(RuntimeError,'binding'):adapter.prove(requirement)
        self.assertEqual(events,['sync','restore','http'])
    def test_secrets_absent_from_metadata_journal_and_refusal(self):
        events=[];runner=Runner(events,post=True);opener=Opener(events)
        with admission.AdmissionJournal(self.jroot) as journal:decision=auth_logout_adapter.admit_logout(journal,self.request,self.adapter(opener,runner))
        metadata=[]
        for path in (self.root/'evidence').rglob('*'):
            if path.is_file() and path.suffix!='.db':metadata.append(path.read_bytes())
        metadata.append((self.jroot/'journal.db').read_bytes());metadata.append(decision.body)
        self.assertNotIn(TOKEN.encode(),b''.join(metadata))

if __name__=='__main__':unittest.main()
