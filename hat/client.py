"""Finite D3 append producer and GET-only observer; no recovery authority.

Stop markers prove ledger completion, NOT process death. Before activation the
controller must independently verify MainPID=0 and an empty producer cgroup.
Observer windows use monotonic request times, with censored boundaries; they are
not physical crash time, an exact RTO, or successful-write availability.
"""
import argparse
import datetime
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

BASE_URL='http://127.0.0.1:18080'
MAX_BODY=1<<20
MAX_LEDGER=4<<20
MAX_SUBMISSIONS=1000
_NO_WRITE={400,401,403,404,409,422}
_EPOCH=re.compile(r'd1-[a-z0-9-]+')
_OP=re.compile(r'd3-[A-Za-z0-9-]{1,125}')


def _utc():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())


def _write(f,value):
    f.write(json.dumps(value,separators=(',',':'),allow_nan=False)+'\n')
    f.flush();os.fsync(f.fileno())


def _checked_path(path):
    p=Path(path).absolute()
    if '..' in p.parts or any(parent.is_symlink() for parent in p.parents):
        raise ValueError('unsafe ledger ancestry')
    s=p.parent.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o7777!=0o700:
        raise ValueError('ledger parent must already be owned and private')
    return p


def _private_file(path):
    p=_checked_path(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        directory=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        return os.fdopen(fd,'w',encoding='utf-8')
    except BaseException:os.close(fd);raise


def _read_private(path,limit):
    p=_checked_path(path)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        s=os.fstat(f.fileno())
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1
                or s.st_mode&0o7777!=0o600 or s.st_size>limit):
            raise ValueError('unsafe or oversized ledger')
        raw=f.read(limit+1)
        if len(raw)>limit:raise ValueError('oversized ledger')
        return raw


def _validate_url(url):
    if not isinstance(url,str) or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in url):
        raise ValueError('invalid loopback URL')
    p=urlsplit(url)
    if (p.scheme!='http' or p.hostname!='127.0.0.1' or p.username is not None
            or p.password is not None or p.query or p.fragment or p.path not in ('','/')
            or p.port is None or not 0<p.port<=65535):
        raise ValueError('invalid loopback URL')
    return 'http://127.0.0.1:'+str(p.port)


def _token(path):
    try:
        line=_read_private(path,MAX_BODY).split(b'\n',1)[0]
        if not line or len(line)>8192:raise ValueError('invalid auth frame')
        value=json.loads(line)
        token=value.get('auth_token') if isinstance(value,dict) and 'event' not in value else None
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*',token):
            raise ValueError('invalid auth frame')
        return token
    except (OSError,ValueError,TypeError):
        raise ValueError('private first smoke auth frame required') from None


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def _http(url,method,body=None,token=None,timeout=5):
    headers={'Content-Type':'application/json'} if body is not None else {}
    if token:headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,method=method,headers=headers,
                               data=json.dumps(body).encode() if body is not None else None)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_RefuseRedirect())
    try:
        try:response=opener.open(req,timeout=timeout)
        except urllib.error.HTTPError as exc:response=exc
        with response:
            status=response.status;raw=response.read(MAX_BODY+1)
    except (OSError,TimeoutError,http.client.HTTPException) as exc:return None,None,exc
    if len(raw)>MAX_BODY:return status,None,ValueError('oversized HTTP response')
    try:value=json.loads(raw)
    except (ValueError,UnicodeDecodeError):value=None
    return status,value,None


def _json_object(line):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate JSON key')
            result[key]=value
        return result
    value=json.loads(line,object_pairs_hook=unique)
    if not isinstance(value,dict):raise ValueError('ledger record must be an object')
    return value


def _stamp(value):
    if type(value.get('time_ns')) is not int or value['time_ns']<=0:raise ValueError('invalid timestamp')
    if 'utc' in value:
        utc=value['utc']
        if not isinstance(utc,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',utc):raise ValueError('invalid UTC stamp')
        datetime.datetime.fromisoformat(utc.replace('Z','+00:00'))


def _valid_id(value):
    return (type(value) in (str,int) and re.fullmatch(r'[0-9]{1,19}',str(value)) is not None
            and 0<int(value)<=2**63-1)


def read_closed_ledger(path,expected_epoch):
    """Return complete classifier events only for the controller's expected epoch.

    Row order establishes submission/outcome chronology. Wall time may step;
    it is descriptive, never the elapsed-time clock. Process-death proof is external.
    """
    if not isinstance(expected_epoch,str) or not _EPOCH.fullmatch(expected_epoch):raise ValueError('invalid expected epoch')
    raw=_read_private(path,MAX_LEDGER)
    lines=raw.splitlines()
    if not raw.endswith(b'\n') or not 2<=len(lines)<=2*MAX_SUBMISSIONS+2:raise ValueError('incomplete or oversized ledger')
    if any(not line or len(line)>8192 for line in lines):raise ValueError('invalid ledger line')
    rows=[_json_object(line) for line in lines];start,stop=rows[0],rows[-1]
    counters=('submitted','acknowledged','rejected','uncertain')
    if (set(start)!={'event','run_id','source_epoch','time_ns','utc'} or start['event']!='start'
            or not isinstance(start['run_id'],str) or not re.fullmatch(r'd3-[0-9a-f]{32}',start['run_id'])
            or start['source_epoch']!=expected_epoch
            or set(stop)!={'event','time_ns','utc',*counters} or stop['event']!='stop'):
        raise ValueError('invalid or mismatched ledger markers')
    _stamp(start);_stamp(stop)
    submitted={};outcomes=set();counts=dict.fromkeys(counters,0)
    for event in rows[1:-1]:
        kind=event.get('event')
        if not isinstance(kind,str) or kind not in counts:raise ValueError('invalid event')
        expected={'event','api','row','time_ns'}|({'id'} if kind=='acknowledged' else set())
        if set(event)!=expected or event['api'] not in ('main_ops','aux_ops'):raise ValueError('invalid event shape')
        row=event['row']
        if (not isinstance(row,dict) or set(row)!={'op_key','payload'}
                or not isinstance(row['op_key'],str) or not _OP.fullmatch(row['op_key'])
                or not isinstance(row['payload'],str) or len(row['payload'])>4096):raise ValueError('invalid operation row')
        _stamp(event);key=event['api'],row['op_key']
        if kind=='submitted':
            if key in submitted:raise ValueError('duplicate submission')
            submitted[key]=row
        else:
            if key not in submitted or key in outcomes or submitted[key]!=row:raise ValueError('unmatched outcome')
            if kind=='acknowledged' and not _valid_id(event['id']):raise ValueError('invalid acknowledgement id')
            outcomes.add(key)
        counts[kind]+=1
    if (len(submitted)>MAX_SUBMISSIONS or set(submitted)!=outcomes
            or any(type(stop[k]) is not int or stop[k]!=counts[k] for k in counters)):
        raise ValueError('incomplete outcomes or inconsistent counters')
    return rows[1:-1]


def _limits(duration,interval,maximum,timeout=5):
    if (any(type(v) not in (int,float) or not math.isfinite(v) for v in (duration,interval,timeout))
            or not 0<duration<=maximum or not .1<=interval<=5 or not 0<timeout<=5):
        raise ValueError('invalid finite client limits')


def produce(token_ledger,output,source_epoch,duration=60,interval=1,base=BASE_URL):
    _limits(duration,interval,120);base=_validate_url(base)
    if not isinstance(source_epoch,str) or not _EPOCH.fullmatch(source_epoch):raise ValueError('invalid source epoch')
    token=_token(token_ledger);stopped=threading.Event()
    old=[signal.signal(s,lambda *_:stopped.set()) for s in (signal.SIGINT,signal.SIGTERM)]
    counts=dict.fromkeys(('submitted','acknowledged','rejected','uncertain'),0)
    try:
        with _private_file(output) as f:
            _write(f,dict(event='start',run_id='d3-'+uuid.uuid4().hex,source_epoch=source_epoch,time_ns=time.time_ns(),utc=_utc()))
            deadline=time.monotonic()+duration
            while not stopped.is_set() and time.monotonic()<deadline and counts['submitted']<MAX_SUBMISSIONS:
                api=('main_ops','aux_ops')[counts['submitted']%2]
                row=dict(op_key='d3-'+uuid.uuid4().hex,payload='D3 fault '+api)
                _write(f,dict(event='submitted',api=api,row=row,time_ns=time.time_ns()));counts['submitted']+=1
                status,value,error=_http(base+'/api/records/v1/'+api,'POST',row,token)
                event=dict(event='uncertain',api=api,row=row,time_ns=time.time_ns())
                if status in _NO_WRITE:event['event']='rejected'
                elif (error is None and status in (200,201) and isinstance(value,dict)
                      and isinstance(value.get('ids'),list) and len(value['ids'])==1
                      and _valid_id(value['ids'][0])):
                    event.update(event='acknowledged',id=value['ids'][0])
                counts[event['event']]+=1;_write(f,event)
                stopped.wait(min(interval,max(0,deadline-time.monotonic())))
            _write(f,dict(event='stop',**counts,time_ns=time.time_ns(),utc=_utc()))
    finally:
        for s,previous in zip((signal.SIGINT,signal.SIGTERM),old):signal.signal(s,previous)


def observe(output,duration=60,interval=1,timeout=5,base=BASE_URL):
    _limits(duration,interval,600,timeout);base=_validate_url(base);stopped=threading.Event()
    old=[signal.signal(s,lambda *_:stopped.set()) for s in (signal.SIGINT,signal.SIGTERM)]
    windows=[];pending=None;last_available=None
    try:
        with _private_file(output) as f:
            _write(f,dict(event='start',time_ns=time.time_ns(),utc=_utc(),clock='monotonic_ns',interval=interval,timeout=timeout))
            deadline=time.monotonic()+duration
            while not stopped.is_set() and time.monotonic()<deadline:
                started=time.monotonic_ns();utc=_utc()
                status,_,error=_http(base+'/api/records/v1/main_ops','GET',timeout=timeout)
                completed=time.monotonic_ns();available=status in (401,403)
                availability='available' if available else ('unexpected_anonymous_access' if status in (200,201) else 'error')
                _write(f,dict(event='observation',started_ns=started,completed_ns=completed,started_utc=utc,completed_utc=_utc(),status=status,available=available,availability=availability,error=type(error).__name__ if error else None))
                if available:
                    if pending is not None:windows.append(pending|dict(through_available_completion_ns=completed,right_censored=False));pending=None
                    last_available=completed
                elif pending is None:
                    pending=dict(after_last_available_ns=last_available,first_unavailable_start_ns=started,through_available_completion_ns=None,left_censored=last_available is None,right_censored=True)
                stopped.wait(min(interval,max(0,deadline-time.monotonic())))
            if pending is not None:windows.append(pending)
            _write(f,dict(event='stop',time_ns=time.time_ns(),utc=_utc(),observation_windows=windows))
    finally:
        for s,previous in zip((signal.SIGINT,signal.SIGTERM),old):signal.signal(s,previous)


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='mode',required=True)
    for mode in ('produce','observe'):
        q=sub.add_parser(mode);q.add_argument('--output',required=True);q.add_argument('--duration',type=float,default=60);q.add_argument('--interval',type=float,default=1);q.add_argument('--base',default=BASE_URL)
        if mode=='produce':q.add_argument('--token-ledger',required=True);q.add_argument('--source-epoch',required=True)
        else:q.add_argument('--timeout',type=float,default=5)
    a=p.parse_args()
    if a.mode=='produce':produce(a.token_ledger,a.output,a.source_epoch,a.duration,a.interval,a.base)
    else:observe(a.output,a.duration,a.interval,a.timeout,a.base)

if __name__=='__main__':main()
