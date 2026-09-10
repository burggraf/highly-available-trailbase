"""Logout-only local transition proof; deliberately not deployable."""
from contextlib import closing
import hashlib,json,os
from pathlib import Path
import re,sqlite3,stat,urllib.error,urllib.request

import admission
import native_adapter

_TOKEN=re.compile(r'[A-Za-z0-9]{86}')
# Deserialization may transiently hold descriptor bytes plus SQLite's copy.
_MAX_SESSION_IMAGE=64*1024*1024

class AuthLogoutAdapter(native_adapter.NativeAdapter):
    """Prove one refresh-token row changed from present to absent."""
    DATABASES={'session'}

    def validate_policy(self,request):
        try:
            if (not isinstance(request,dict) or request.get('method')!='POST'
                    or request.get('path')!='/api/auth/v1/logout'
                    or request.get('headers')!={'content-type':'application/json'}
                    or not isinstance(request.get('body'),bytes)):
                raise ValueError
            body=native_adapter._json(request['body'])
            token=body.get('refresh_token') if isinstance(body,dict) and set(body)=={'refresh_token'} else None
            if not isinstance(token,str) or not _TOKEN.fullmatch(token): raise ValueError
        except (TypeError,ValueError,UnicodeDecodeError):
            raise ValueError('unsupported logout request') from None
        return token

    def _directory(self,operation):
        self._revalidate(self.evidence)
        directory=self.evidence/operation;directory.mkdir(mode=0o700)
        value=directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(value.st_mode) or value.st_uid!=os.geteuid()
                or value.st_mode&0o077):
            raise RuntimeError('logout operation directory differs')
        self.identities[directory]=(value.st_dev,value.st_ino,'directory')
        return directory

    def _sync_restore(self,directory,label):
        source=self.databases['session']
        for path in (self.litestream,self.config,self.socket_path,source,self.evidence,directory):self._revalidate(path)
        if hashlib.sha256(self.litestream.read_bytes()).hexdigest()!=self.binary_sha256:
            raise RuntimeError('logout adapter binary content changed')
        sync=self._command(directory,label+'-sync',[self.litestream,'sync','-socket',self.socket_path,
            '-timeout','10','-wait','-json',source])
        try:
            position=native_adapter._json(sync.stdout)
            if (not isinstance(position,dict) or set(position)!={'db_path','txid','replica_txid','duration_ms'}
                    or position['db_path']!=str(source) or type(position['txid']) is not int
                    or position['txid']<=0 or position['replica_txid']!=position['txid']
                    or type(position['duration_ms']) is not int or position['duration_ms']<0):raise ValueError
        except (TypeError,ValueError,UnicodeDecodeError):
            raise RuntimeError('logout sync result differs') from None
        restored=directory/(label+'.restore')
        self._command(directory,label+'-restore',[self.litestream,'restore','-config',self.config,
            '-txid',f"{position['txid']:016x}",'-integrity-check','none','-o',restored,source])
        self._revalidate(directory)
        descriptor=os.open(restored,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            value=os.fstat(descriptor)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid!=os.geteuid() or value.st_nlink!=1
                    or value.st_size>_MAX_SESSION_IMAGE):raise RuntimeError('logout restored image differs')
            os.fchmod(descriptor,0o600);os.fsync(descriptor);identity=(value.st_dev,value.st_ino)
        finally:os.close(descriptor)
        current=restored.lstat()
        if ((current.st_dev,current.st_ino)!=identity or restored.is_symlink()
                or self.root not in restored.resolve().parents):raise RuntimeError('logout image identity changed')
        output=directory/(label+'.db');self._revalidate(directory);os.replace(restored,output)
        folder=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(folder)
        finally:os.close(folder)
        value=output.lstat()
        if ((value.st_dev,value.st_ino)!=identity or value.st_mode&0o077 or not stat.S_ISREG(value.st_mode)
                or value.st_nlink!=1):raise RuntimeError('logout restored image differs')
        return position,output,(value.st_dev,value.st_ino,value.st_size)

    def _presence(self,image,token,identity):
        descriptor=os.open(image,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            value=os.fstat(descriptor)
            if ((value.st_dev,value.st_ino,value.st_size)!=identity or not stat.S_ISREG(value.st_mode)
                    or value.st_uid!=os.geteuid() or value.st_mode&0o077 or value.st_nlink!=1
                    or value.st_size>_MAX_SESSION_IMAGE):
                raise RuntimeError('logout image identity changed')
            chunks=[];remaining=value.st_size
            while remaining:
                chunk=os.read(descriptor,min(1024*1024,remaining))
                if not chunk:raise RuntimeError('logout image truncated')
                chunks.append(chunk);remaining-=len(chunk)
            if (os.fstat(descriptor).st_dev,os.fstat(descriptor).st_ino,os.fstat(descriptor).st_size)!=identity:
                raise RuntimeError('logout image identity changed')
        finally:os.close(descriptor)
        raw=b''.join(chunks);digest=hashlib.sha256(raw).hexdigest()
        try:
            with closing(sqlite3.connect(':memory:')) as db:
                db.deserialize(raw);db.execute('PRAGMA ignore_check_constraints=ON')
                if db.execute('PRAGMA integrity_check').fetchone()!=('ok',) or db.execute('PRAGMA foreign_key_check').fetchall():
                    raise ValueError
                count=db.execute('SELECT count(*) FROM _session WHERE refresh_token=? AND expires>unixepoch()',(token,)).fetchone()
            if count is None or type(count[0]) is not int:raise ValueError
            return count[0],digest
        except (sqlite3.Error,ValueError):
            raise RuntimeError('logout session image differs') from None

    def forward(self,request):
        token=self.validate_policy(request);operation=request['operation_id']
        if operation in self.contexts:raise RuntimeError('logout operation already forwarded')
        directory=self._directory(operation)
        predecessor,image,identity=self._sync_restore(directory,'predecessor')
        presence,predecessor_digest=self._presence(image,token,identity)
        if presence!=1:raise RuntimeError('logout predecessor token absent')
        web=urllib.request.Request(self.base_url+request['path'],request['body'],request['headers'],method='POST')
        try:response=self.opener.open(web,timeout=5)
        except urllib.error.HTTPError as error:response=error
        with response:
            raw=response.read(native_adapter.MAX_BODY+1);status=response.status
        if len(raw)>native_adapter.MAX_BODY or type(status) is not int or not 100<=status<=599:
            raise ValueError('invalid logout upstream response')
        digest,database=admission._request(request)
        binding={'operation_id':operation,'request_digest':digest,'epoch':request['epoch'],
                 'writer_boot':request['writer_boot'],'database':database}
        if database!='session':raise RuntimeError('logout request binding differs')
        self.contexts[operation]={'binding':binding,'token':token,'status':status,'response_body':raw,
            'predecessor_txid':predecessor['txid'],'predecessor_sha256':predecessor_digest,
            'directory':directory}
        return {'status':status,'response_body':raw,'mutation':'completed' if 200<=status<=299 else 'possible'}

    def prove(self,requirement):
        operation=requirement.get('operation_id') if isinstance(requirement,dict) else None
        context=self.contexts.pop(operation,None)
        if (context is None or not isinstance(requirement,dict)
                or context['binding']!={key:requirement.get(key) for key in context['binding']}):
            raise RuntimeError('logout forward binding absent')
        if context['status']!=200 or context['response_body']!=b'':
            raise RuntimeError('logout upstream response differs')
        successor,image,identity=self._sync_restore(context['directory'],'successor')
        presence,successor_digest=self._presence(image,context['token'],identity)
        if successor['txid']<=context['predecessor_txid'] or presence!=0:
            raise RuntimeError('logout transition proof differs')
        evidence_id=f"logout-{operation}-session-{context['predecessor_txid']}-{successor['txid']}"
        record={'operation_id':operation,'request_digest':requirement['request_digest'],'epoch':requirement['epoch'],
            'writer_boot':requirement['writer_boot'],'database':'session','predecessor_txid':context['predecessor_txid'],
            'txid':successor['txid'],'replica_txid':successor['replica_txid'],'image_verified':True,
            'evidence_id':evidence_id,'transition':'PRESENT_TO_ABSENT','predecessor_sha256':context['predecessor_sha256'],
            'successor_sha256':successor_digest}
        self._revalidate(context['directory'])
        native_adapter._write(context['directory']/'proof.json',json.dumps(record,separators=(',',':')).encode())
        return {key:record[key] for key in ('operation_id','request_digest','epoch','writer_boot','database',
            'txid','replica_txid','image_verified','evidence_id')}

def admit_logout(journal,request,adapter):
    adapter.validate_policy(request)
    return admission.admit(journal,request,adapter.forward,adapter.prove)
