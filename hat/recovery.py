"""D3 fixed-fixture recovery contracts and the B-to-A recovery driver.

``/etc/hat-control/recovery-input.json`` is a private root-owned JSON object with
exactly these fields::

  authority_operation: 32 lowercase hex ID of the completed B-writer operation
  source_epoch/source_boot: captured pre-fault B epoch and boot ID
  source_health: private pre-producer node probe, authority_operation and observed_ns
  source_config/source_replica: verbatim pre-fault B node object and replica text
  candidate_epoch/candidate_boot: quarantined cold A's configured epoch and boot
  protected_ledger: absolute protected history path below /var/lib/hat-control
  protected_baseline: absolute report path below that root; source epoch, valid
                      three-DB positions/signatures and canonical checks=PASS
  fault_ledger: absolute closed generated D3 ledger path below that root
  producer_unit: hat-d3-client-<32 lowercase hex>.service
  producer_cgroup: /sys/fs/cgroup/system.slice/<producer_unit>

The input and referenced artifacts are bounded, private, owned, singly linked
regular files; artifact ancestry below the controller root is private and has no
symlinks. The driver never powers a node off and intentionally leaves the ten
verified recovery phases unfinished for the separately authorized rejoin tail.
"""
from contextlib import closing
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import time

import client
import descriptor
import node


def _safe_timestamp(value):
    try:
        return datetime.datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo
    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        return None


def _safe_utc(value):
    try:
        if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value): return False
        datetime.datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ')
        return True
    except (ValueError, TypeError, OverflowError, RecursionError):
        return False


def restore_endpoint(plan, source, target, minimum):
    """Validate the pinned native JSON plan; the finite restore remains mandatory."""
    try:
        if (set(plan)!={'source','target_path','replica','min_txid','max_txid','files'}
                or plan['source']!=source or plan['target_path']!=target or plan['replica']!='s3'
                or type(minimum) is not int or not 0<minimum<2**64
                or not isinstance(plan['files'],list) or not 0<len(plan['files'])<=10000):
            raise ValueError('invalid native restore plan')
        low,high=node.txid(plan['min_txid']),node.txid(plan['max_txid'])
        if not 0<low<=high or high<minimum:raise ValueError('plan is invalid or older than protected baseline')
        spans=[];seen=set()
        for file in plan['files']:
            if (set(file)!={'level','name','min_txid','max_txid','size','timestamp'}
                    or type(file['level']) is not int or not 0<=file['level']<=9
                    or type(file['size']) is not int or not 0<file['size']<2**63):
                raise ValueError('invalid plan file metadata')
            a,b=node.txid(file['min_txid']),node.txid(file['max_txid'])
            key=file['level'],file['name']
            if (not low<=a<=b<=high or file['name']!=f'{a:016x}-{b:016x}.ltx' or key in seen
                    or _safe_timestamp(file['timestamp']) is None):
                raise ValueError('invalid plan file identity or range')
            seen.add(key);spans.append((a,b))
        if min(a for a,b in spans)!=low or max(b for a,b in spans)!=high:raise ValueError('plan endpoints disagree')
        return high
    except (KeyError,TypeError,AttributeError,OverflowError,ValueError,RecursionError):
        raise ValueError('malformed native restore plan') from None


def classify_fault(events, data):
    """Classify only generated append operations in the chosen recovery image."""
    submitted={};outcomes={}
    for event in events:
        if not isinstance(event,dict) or not {'event','api','row'}<=set(event) or set(event)-{'event','api','row','id','time_ns','status','error'}:
            raise ValueError('malformed fault event')
        kind,api,row=event['event'],event['api'],event['row']
        if (kind not in ('submitted','acknowledged','rejected','uncertain') or api not in ('main_ops','aux_ops')
                or not isinstance(row,dict) or set(row)!={'op_key','payload'}
                or not isinstance(row['op_key'],str) or not re.fullmatch('d3-[A-Za-z0-9-]{1,125}',row['op_key'])
                or not isinstance(row['payload'],str) or len(row['payload'])>4096):
            raise ValueError('invalid fault operation')
        key=api,row['op_key']
        if kind=='submitted':
            if key in submitted:raise ValueError('duplicate submission')
            submitted[key]=row
        else:
            if key not in submitted or key in outcomes or submitted[key]!=row:raise ValueError('unmatched or duplicate outcome')
            if kind=='acknowledged' and (type(event.get('id')) not in (str,int) or not str(event['id']).isdigit()):raise ValueError('invalid acknowledgement ID')
            outcomes[key]=event
    result={name:[] for name in ('recovered','lost','ambiguous','unacknowledged_recovered','rejected')}
    for api in ('main_ops','aux_ops'):
        with closing(sqlite3.connect((data/(api.removesuffix('_ops')+'.db')).as_uri()+'?mode=ro',uri=True)) as db:
            for key,row in submitted.items():
                if key[0]!=api:continue
                found=db.execute('SELECT id,payload FROM hat_ops WHERE op_key=?',(key[1],)).fetchall()
                outcome=outcomes.get(key,{});kind=outcome.get('event')
                if len(found)>1 or (found and found[0][1]!=row['payload']):raise ValueError('recovered payload differs')
                if kind=='acknowledged':
                    if found and str(found[0][0])!=str(outcome['id']):raise ValueError('acknowledged row identity differs')
                    category='recovered' if found else 'lost'
                elif kind=='rejected':
                    if found:raise ValueError('rejected operation exists in recovery image')
                    category='rejected'
                else:category='unacknowledged_recovered' if found else 'ambiguous'
                result[category].append('/'.join(key))
    return {name: sorted(values) for name, values in result.items()}


INPUT_FIELDS = {
    'authority_operation', 'source_epoch', 'source_boot', 'source_config', 'source_health',
    'source_replica', 'candidate_epoch', 'candidate_boot', 'protected_ledger',
    'protected_baseline', 'fault_ledger', 'producer_unit', 'producer_cgroup',
}
MAX_INPUT = 1 << 20
MAX_ARTIFACT = 4 << 20
_EPOCH = re.compile(r'd1-[a-z0-9-]{1,125}')
_OPERATION = re.compile(r'[0-9a-f]{32}')
_PRODUCER = re.compile(r'hat-d3-client-([0-9a-f]{32})\.service')
_ACCEPTANCE_SCHEMA = 'hat-restore-acceptance-1'
_AUTHORITY_SCHEMA = 'hat-restore-input-authority-1'
_DBS = ('main', 'session', 'aux')
_HEX64 = re.compile(r'[0-9a-f]{64}')


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError('invalid canonical JSON value') from exc


def _unique_pairs(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate JSON key')
        value[key]=item
    return value


def parse_canonical_json(raw):
    if not isinstance(raw, (bytes, bytearray)) or not 0 < len(raw) <= MAX_INPUT:
        raise ValueError('invalid canonical JSON bytes')
    try:
        value=json.loads(bytes(raw).decode('ascii'), object_pairs_hook=_unique_pairs)
        stack=[(value,0)]; containers=0
        while stack:
            item,depth=stack.pop()
            if isinstance(item,dict): children=item.values()
            elif isinstance(item,list): children=item
            else: continue
            containers += 1
            if depth > 512 or containers > 100000: raise ValueError('invalid canonical JSON bytes')
            stack.extend((child,depth+1) for child in children)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError('invalid canonical JSON bytes') from None
    try:
        if canonical_json(value) != bytes(raw): raise ValueError('noncanonical JSON bytes')
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError('invalid canonical JSON bytes') from None
    return value


def _acceptance_operation(value):
    if not isinstance(value, dict) or set(value) != {'id','source','target','source_epoch','new_epoch'}:
        raise ValueError('invalid restore operation')
    if (not isinstance(value['id'], str) or not _OPERATION.fullmatch(value['id'])
            or (value['source'], value['target']) not in (('A','B'),('B','A'))):
        raise ValueError('invalid restore operation')
    for name in ('source_epoch','new_epoch'):
        if not isinstance(value[name], str) or not _EPOCH.fullmatch(value[name]):
            raise ValueError('invalid restore epoch')
    if value['new_epoch'] != 'd1-' + value['id'] or value['source_epoch'] == value['new_epoch']:
        raise ValueError('restore epoch binding differs')
    return value


def derive_restore_profile(operation, phase, has_fault):
    operation = _acceptance_operation(operation)
    if type(has_fault) is not bool: raise ValueError('invalid restore fault selection')
    matrix = {
        ('A','B','compare',False): ('comparison', operation['source_epoch'], 5, False),
        ('A','B','reconciled-compare',False): ('comparison', operation['source_epoch'], 5, True),
        ('A','B','baseline',False): ('baseline', operation['new_epoch'], 7, False),
        ('A','B','verification-baseline',False): ('baseline', operation['new_epoch'], 9, True),
        ('A','B','new-writes',False): ('fresh-writes', operation['new_epoch'], 9, False),
        ('B','A','compare',True): ('recovery-comparison', operation['source_epoch'], 5, False),
        ('B','A','baseline',False): ('baseline', operation['new_epoch'], 7, False),
        ('B','A','new-writes',False): ('fresh-writes', operation['new_epoch'], 9, False),
    }
    try: return matrix[(operation['source'], operation['target'], phase, type(has_fault) is bool and has_fault)]
    except KeyError as exc: raise ValueError('unsupported restore acceptance phase') from exc


def _authority(value, operation, profile):
    if (not isinstance(value, dict) or set(value) != {'schema','operation','origin','ledger','support','binaries'}
            or not isinstance(value.get('support'), dict) or not isinstance(value.get('binaries'), dict)):
        raise ValueError('invalid restore input authority')
    if value['schema'] != _AUTHORITY_SCHEMA or value['operation'] != operation['id']:
        raise ValueError('restore input authority differs')
    allowed = {'d2-preflight','d3-recovery-input','current-verify-exclusive'}
    origin=value['origin']
    valid_origin = ((origin=='d2-preflight' and operation['source']=='A' and operation['target']=='B' and profile in ('comparison','baseline'))
                    or (origin=='d3-recovery-input' and operation['source']=='B' and operation['target']=='A' and profile in ('recovery-comparison','baseline'))
                    or (origin=='current-verify-exclusive' and profile=='fresh-writes'))
    if origin not in allowed or not valid_origin:
        raise ValueError('restore input authority origin differs')
    ledger=value['ledger']
    if (not isinstance(ledger,dict) or set(ledger) != {'path','device','inode','mode','uid','links','bytes','sha256'}
            or not isinstance(ledger['path'],str) or not Path(ledger['path']).is_absolute() or os.path.normpath(ledger['path']) != ledger['path']
            or any(type(ledger[k]) is not int or ledger[k] < 0 for k in ('device','uid'))
            or type(ledger['inode']) is not int or ledger['inode'] <= 0
            or type(ledger['mode']) is not int or ledger['mode'] != 0o600
            or type(ledger['links']) is not int or ledger['links'] != 1
            or type(ledger['bytes']) is not int or not 0 < ledger['bytes'] <= MAX_ARTIFACT
            or not _HEX64.fullmatch(ledger['sha256'])):
        raise ValueError('invalid restore ledger authority')
    if origin == 'd3-recovery-input':
        match = re.fullmatch(r'/var/lib/hat-control/([0-9a-f]{32})/ledger\.jsonl', ledger['path'])
        if not match or match.group(1) == operation['id']:
            raise ValueError('restore ledger authority path differs')
    else:
        expected_name='new-writes.jsonl' if origin=='current-verify-exclusive' else 'ledger.jsonl'
        if ledger['path'] != '/var/lib/hat-control/'+operation['id']+'/'+expected_name:
            raise ValueError('restore ledger authority path differs')
    if set(value['binaries']) != {'trail','litestream'} or any(not isinstance(v,str) or not _HEX64.fullmatch(v) for v in value['binaries'].values()):
        raise ValueError('invalid restore binary authority')
    required={'config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem'}
    if set(value['support']) != required or any(not isinstance(v,str) or not _HEX64.fullmatch(v) for v in value['support'].values()):
        raise ValueError('invalid restore support authority')


def _validate_acceptance_request(request, operation):
    operation = _acceptance_operation(operation)
    if not isinstance(request,dict) or set(request) != {'schema','operation','phase','source','target','epoch','positions','profile','inputs'}:
        raise ValueError('invalid restore acceptance request')
    if request['schema'] != _ACCEPTANCE_SCHEMA or request['operation'] != operation['id']:
        raise ValueError('restore request identity differs')
    profile, epoch, _, _ = derive_restore_profile(operation, request['phase'], request['profile']=='recovery-comparison')
    if (request['source'],request['target'],request['epoch'],request['profile']) != (operation['source'],operation['target'],epoch,profile):
        raise ValueError('restore request binding differs')
    positions=request['positions']
    if set(positions) != set(_DBS) or any(type(v) is not int or not 0 < v < 2**64 for v in positions.values()):
        raise ValueError('invalid restore positions')
    inputs=request['inputs']
    required={'replica_config_sha256','ledger_sha256','ledger_authority','restore_points','support','binaries'}
    if not isinstance(inputs,dict) or not required <= set(inputs):
        raise ValueError('invalid restore request inputs')
    if not _HEX64.fullmatch(inputs['replica_config_sha256']) or not _HEX64.fullmatch(inputs['ledger_sha256']):
        raise ValueError('invalid restore input hashes')
    _authority(inputs['ledger_authority'],operation,profile)
    if inputs['ledger_authority']['ledger']['sha256'] != inputs['ledger_sha256'] or inputs['support'] != inputs['ledger_authority']['support'] or inputs['binaries'] != inputs['ledger_authority']['binaries']:
        raise ValueError('restore request authority mismatch')
    points=inputs['restore_points']
    if set(points) != set(_DBS): raise ValueError('invalid restore points')
    for db in _DBS:
        if set(points[db]) != {'source','position'} or points[db]['source'] != '/var/lib/hat-demo/depot/data/'+db+'.db' or points[db]['position'] != positions[db]:
            raise ValueError('restore point binding differs')
    if profile == 'recovery-comparison':
        extra={'fault_ledger_sha256','fault_operations','fault_operation_count','fault_operations_sha256'}
        if set(inputs) != required|extra or not isinstance(inputs['fault_operations'],list) or type(inputs['fault_operation_count']) is not int or inputs['fault_operation_count'] != len(inputs['fault_operations']):
            raise ValueError('invalid fault request binding')
        if inputs['fault_operations'] != sorted(set(inputs['fault_operations'])) or any(not isinstance(v,str) or not re.fullmatch(r'(?:main|aux)_ops/d3-[A-Za-z0-9-]{1,125}',v) for v in inputs['fault_operations']):
            raise ValueError('invalid fault request operations')
        if not _HEX64.fullmatch(inputs['fault_ledger_sha256']) or hashlib.sha256(canonical_json(inputs['fault_operations'])).hexdigest() != inputs['fault_operations_sha256']:
            raise ValueError('invalid fault request hashes')
    elif set(inputs) != required:
        raise ValueError('unexpected fault request fields')
    return request


def validate_acceptance_request(request, operation):
    try: return _validate_acceptance_request(request, operation)
    except ValueError: raise
    except (KeyError,TypeError,AttributeError,OverflowError) as exc:
        raise ValueError('invalid restore acceptance request') from exc


def parse_acceptance_request(raw, operation):
    return validate_acceptance_request(parse_canonical_json(raw), operation)


def _canonical_id(value):
    if type(value) is int:
        if 0 < value <= 2**63-1: return str(value)
    elif isinstance(value,str) and re.fullmatch(r'[1-9][0-9]{0,18}',value) and int(value) <= 2**63-1:
        return value
    raise ValueError('invalid record identity')


def fault_operations(events):
    try:
        if (not isinstance(events,list) or not 2 <= len(events) <= 2002
                or not isinstance(events[0],dict) or not isinstance(events[-1],dict)):
            raise ValueError('invalid closed fault ledger')
        start,stop=events[0],events[-1]
        stamp=re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
        if (set(start) != {'event','run_id','source_epoch','time_ns','utc'} or start.get('event')!='start'
                or not isinstance(start.get('run_id'),str) or not re.fullmatch(r'd3-[0-9a-f]{32}',start['run_id'])
                or not isinstance(start.get('source_epoch'),str) or not _EPOCH.fullmatch(start['source_epoch'])
                or type(start.get('time_ns')) is not int or start['time_ns']<=0
                or not isinstance(start.get('utc'),str) or not stamp.fullmatch(start['utc'])):
            raise ValueError('invalid closed fault ledger')
        if not _safe_utc(start['utc']): raise ValueError('invalid closed fault ledger')
        submitted={};outcomes={};counts={'submitted':0,'acknowledged':0,'rejected':0,'uncertain':0};previous=start['time_ns']
        for event in events[1:-1]:
            if not isinstance(event,dict): raise ValueError('invalid fault event')
            kind=event.get('event');expected={'event','api','row','time_ns'}|({'id'} if kind=='acknowledged' else set())
            if (kind not in counts or set(event)!=expected or event.get('api') not in ('main_ops','aux_ops')
                    or type(event.get('time_ns')) is not int or event['time_ns']<=previous):
                raise ValueError('invalid fault event')
            previous=event['time_ns'];row=event.get('row')
            if (not isinstance(row,dict) or set(row)!={'op_key','payload'} or not isinstance(row['op_key'],str)
                    or not re.fullmatch(r'd3-[A-Za-z0-9-]{1,125}',row['op_key'])
                    or not isinstance(row['payload'],str) or len(row['payload'])>4096): raise ValueError('invalid fault event')
            key=(event['api'],row['op_key'])
            if kind=='submitted':
                if key in submitted or len(submitted)>=1000: raise ValueError('duplicate or excessive fault submission')
                submitted[key]=row
            else:
                if key not in submitted or key in outcomes or submitted[key]!=row: raise ValueError('invalid fault outcome ordering')
                if kind=='acknowledged': _canonical_id(event.get('id'))
                outcomes[key]=kind
            counts[kind]+=1
        if (set(stop)!={'event','submitted','acknowledged','rejected','uncertain','time_ns','utc'} or stop.get('event')!='stop'
                or type(stop.get('time_ns')) is not int or stop['time_ns']<=previous
                or not isinstance(stop.get('utc'),str) or not stamp.fullmatch(stop['utc'])): raise ValueError('invalid fault stop')
        if not _safe_utc(stop['utc']): raise ValueError('invalid fault stop')
        if any(type(stop.get(k)) is not int or stop[k]!=counts[k] for k in counts) or set(submitted)!=set(outcomes):
            raise ValueError('incomplete fault ledger')
        return sorted(api+'/'+key for api,key in submitted)
    except ValueError: raise
    except (KeyError,TypeError,AttributeError,OverflowError) as exc: raise ValueError('invalid closed fault ledger') from exc


def validate_fault_outcomes(value, events):
    try:
        categories=('recovered','lost','ambiguous','unacknowledged_recovered','rejected');pattern=re.compile(r'(?:main|aux)_ops/d3-[A-Za-z0-9-]{1,125}')
        if (not isinstance(value,dict) or set(value)!=set(categories)
                or any(not isinstance(value[k],list) or value[k]!=sorted(value[k])
                       or any(not isinstance(item,str) or not pattern.fullmatch(item) for item in value[k]) for k in categories)):
            raise ValueError('invalid fault outcomes')
        expected=set(fault_operations(events));flattened=[item for k in categories for item in value[k]]
        if len(flattened)!=len(set(flattened)) or set(flattened)!=expected or value['lost']:
            raise ValueError('fault outcomes are incomplete or acknowledge loss')
        kinds={event['api']+'/'+event['row']['op_key']:event['event'] for event in events[1:-1] if event['event']!='submitted'}
        for item in value['recovered']:
            if kinds[item]!='acknowledged': raise ValueError('fault recovery semantics differ')
        for item in value['rejected']:
            if kinds[item]!='rejected': raise ValueError('fault rejection semantics differ')
        for category in ('ambiguous','unacknowledged_recovered'):
            if any(kinds[item]!='uncertain' for item in value[category]): raise ValueError('fault uncertainty semantics differ')
        return value
    except ValueError: raise
    except (KeyError,TypeError,AttributeError) as exc: raise ValueError('invalid fault outcomes') from exc


def _validate_acceptance_result(result, request, operation, events=None):
    validate_acceptance_request(request, operation)
    if not isinstance(result,dict) or set(result) != {'schema','request','request_sha256','databases','signature','checks'} or result['schema'] != _ACCEPTANCE_SCHEMA or result['request'] != request or result['request_sha256'] != hashlib.sha256(canonical_json(request)).hexdigest():
        raise ValueError('invalid restore acceptance result')
    if set(result['databases']) != set(_DBS) or set(result['signature']) != set(_DBS): raise ValueError('invalid restore result databases')
    for db in _DBS:
        item=result['databases'][db]
        if set(item) != {'position','sha256','integrity','foreign_keys'} or item['position'] != request['positions'][db] or not _HEX64.fullmatch(item['sha256']) or item['integrity'] != 'PASS' or item['foreign_keys'] != 'PASS': raise ValueError('invalid restore database result')
        if not _HEX64.fullmatch(result['signature'][db]): raise ValueError('invalid restore signature')
    if request['profile'] == 'recovery-comparison':
        if set(result['checks']) != {'records','authentication','fault_outcomes','acknowledged_loss'} or result['checks']['acknowledged_loss'] != 'NONE':
            raise ValueError('invalid recovery restore checks')
        outcomes=result['checks']['fault_outcomes']
        categories=('recovered','lost','ambiguous','unacknowledged_recovered','rejected')
        pattern=re.compile(r'(?:main|aux)_ops/d3-[A-Za-z0-9-]{1,125}')
        if (not isinstance(outcomes,dict) or set(outcomes) != set(categories)
                or any(not isinstance(outcomes[k],list) or outcomes[k] != sorted(outcomes[k])
                       or any(not isinstance(item,str) or not pattern.fullmatch(item) for item in outcomes[k]) for k in categories)):
            raise ValueError('invalid recovery fault outcomes')
        expected=set(request['inputs']['fault_operations']); flattened=[v for k in categories for v in outcomes[k]]
        if len(flattened) != len(set(flattened)) or set(flattened) != expected or outcomes['lost']:
            raise ValueError('invalid recovery fault outcome binding')
        if events is not None:
            validate_fault_outcomes(outcomes, events)
        if result['checks']['records'] != 'PASS' or result['checks']['authentication'] != 'PASS': raise ValueError('invalid restore checks')
    elif result['checks'] != {'records':'PASS','authentication':'PASS'}:
        raise ValueError('invalid restore checks')
    return result


def validate_acceptance_result(result, request, operation, events=None):
    try: return _validate_acceptance_result(result, request, operation, events)
    except ValueError: raise
    except (KeyError,TypeError,AttributeError,OverflowError) as exc:
        raise ValueError('invalid restore acceptance result') from exc


def parse_acceptance_result(raw, request, operation):
    return validate_acceptance_result(parse_canonical_json(raw), request, operation)


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def _owned_bytes(path, limit, root=None):
    """Read one bounded owned, private, singly linked regular file without following it."""
    path = Path(path).absolute()
    if '..' in path.parts: raise ValueError('artifact path traversal is forbidden')
    if root is not None:
        root = Path(root).absolute()
        try: path.relative_to(root)
        except ValueError as exc: raise ValueError('artifact is outside private controller root') from exc
        parent = path.parent
        while True:
            s = parent.lstat()
            if (not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode)
                    or s.st_uid != os.geteuid() or s.st_mode & 0o077):
                raise ValueError('artifact directory is not private and owned')
            if parent == root: break
            if root not in parent.parents: raise ValueError('artifact ancestry differs')
            parent = parent.parent
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_nlink != 1
                or s.st_mode & 0o077 or not 0 < s.st_size <= limit):
            raise ValueError('artifact must be bounded, private, owned, regular and singly linked')
        raw = b''
        while len(raw) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not part: break
            raw += part
        if len(raw) > limit: raise ValueError('oversized artifact')
        return raw
    finally:
        os.close(fd)


def _write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _write_json(path, value):
    _write_private(path, json.dumps(value, separators=(',', ':'), allow_nan=False).encode())


def _cut_report(value, epoch=None):
    """Validate the canonical acceptance result; epoch comes from result.request."""
    from transition import validate_cut
    if not isinstance(value, dict) or set(value) != {'schema','request','request_sha256','databases','signature','checks'}:
        raise ValueError('restore report is not canonical')
    request = value['request']; positions = request['positions']; validate_cut(positions)
    checks=value['checks']
    recovery_checks=(request.get('profile')=='recovery-comparison'
                     and isinstance(checks,dict)
                     and set(checks)=={'records','authentication','fault_outcomes','acknowledged_loss'}
                     and checks['records']=='PASS' and checks['authentication']=='PASS'
                     and checks['acknowledged_loss']=='NONE')
    if (not isinstance(value['signature'], dict) or set(value['signature']) != set(node.DBS)
            or checks != {'records':'PASS','authentication':'PASS'} and not recovery_checks
            or (epoch is not None and request.get('epoch') != epoch)):
        raise ValueError('restore report signature, checks, or epoch differs')
    return value


def _source_config(value, epoch):
    required = {'role', 'epoch', 'hostname', 'binaries', 'support'}
    binaries = value.get('binaries') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or not required <= set(value) or value['role'] != 'writer'
            or value['epoch'] != epoch or not isinstance(value['hostname'], str) or not value['hostname']
            or not isinstance(binaries, dict) or set(binaries) != {'trail', 'litestream'}
            or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
                   for v in binaries.values())
            or value.get('bootstrap', False) is not False):
        raise ValueError('captured source config is not the existing writer config')
    # validate_support enforces the exact fixed support key set; local files are checked later.
    required_support = {'config.textproto', 'migrations/main/U100__hat_ops.sql',
                        'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
                        'secrets/keys/public_key.pem'}
    support = value.get('support')
    if (not isinstance(support, dict) or set(support) != required_support
            or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
                   for v in support.values())):
        raise ValueError('captured source support identity is invalid')
    return value


def _replica_config(value, epoch):
    if isinstance(value,str): raw=value.encode()
    elif isinstance(value,(bytes,bytearray)): raw=bytes(value)
    else: raise ValueError('captured replica config is invalid')
    if (not 0 < len(raw) <= MAX_INPUT or b"\r" in raw or b"\x00" in raw
            or raw.startswith(b"\xef\xbb\xbf") or not raw.endswith(b"\n")):
        raise ValueError('captured replica config is invalid')
    try: text=raw.decode('utf-8')
    except UnicodeDecodeError as exc: raise ValueError('captured replica config is invalid') from exc
    lines=raw.split(b"\n")[:-1]
    if any(len(line)>8192 for line in lines): raise ValueError('captured replica config is invalid')
    paths=[]
    for line in text.split('\n')[:-1]:
        if re.match(r'^[ \t]*path:', line):
            match=re.fullmatch(r'[ \t]*path:[ \t]*([^#\s]+)[ \t]*(?:#.*)?',line)
            if not match: raise ValueError('captured replica config is invalid')
            paths.append(match.group(1))
    expected={'demos/'+epoch+'/'+db for db in node.DBS}
    if len(paths)!=3 or set(paths)!=expected: raise ValueError('captured replica config does not bind the source epoch')
    return value

def _protected_ledger(raw):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_ARTIFACT or b"\x00" in raw or not raw.endswith(b"\n"):
        raise ValueError('protected ledger is incomplete or oversized')
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError('protected ledger encoding is invalid')
    try:
        lines=raw.split(b"\n")[:-1]
        if not lines or any(not line or len(line)>8192 for line in lines): raise ValueError
        rows=[parse_canonical_json(line) for line in lines]
    except (TypeError,ValueError,UnicodeError,json.JSONDecodeError) as exc:
        raise ValueError('protected ledger is malformed') from exc
    if not isinstance(rows[0],dict) or set(rows[0]) != {'auth_token','retained_refresh','revoked_refresh'} or any(type(rows[0][k]) is not str or not rows[0][k] for k in rows[0]):
        raise ValueError('protected ledger auth frame is invalid')
    seen_keys=set();seen_ids=set();auth_pairs={(rows[0]['retained_refresh'],rows[0]['revoked_refresh'])};submitted=[];index=1
    for api in ('main_ops','aux_ops'):
        if index+1 >= len(rows): raise ValueError('protected ledger current pairs are incomplete')
        sub, ack=rows[index], rows[index+1]
        if (set(sub) != {'event','api','row','time_ns'} or sub.get('event')!='submitted' or sub.get('api')!=api
                or set(ack) != {'event','api','row','id','time_ns'} or ack.get('event')!='acknowledged' or ack.get('api')!=api
                or sub.get('row') != ack.get('row') or not isinstance(sub.get('row'),dict) or set(sub['row']) != {'op_key','payload'}
                or not isinstance(sub['row']['op_key'],str) or not re.fullmatch(r'd1-[A-Za-z0-9-]{1,125}',sub['row']['op_key'])
                or not isinstance(sub['row']['payload'],str) or len(sub['row']['payload'])>4096
                or type(sub.get('time_ns')) is not int or sub['time_ns']<=0 or type(ack.get('time_ns')) is not int or ack['time_ns']<=0
                or type(ack.get('id')) not in (str,int)):
            raise ValueError('protected ledger operation is invalid')
        key=api+'/'+sub['row']['op_key']; ident=_canonical_id(ack['id'])
        if key in seen_keys or ident in seen_ids: raise ValueError('protected ledger operation is duplicated')
        seen_keys.add(key); seen_ids.add(ident); submitted.append(key); index += 2
    if index >= len(rows) or rows[index] != {'event':'smoke_pass'}: raise ValueError('protected ledger smoke marker is invalid')
    index += 1
    while index < len(rows):
        row=rows[index]
        if not isinstance(row,dict): raise ValueError('protected ledger historical frame is invalid')
        if set(row)=={'event','api','row','id','time_ns'} and row.get('event')=='acknowledged':
            payload=row['row']
            if (row['api'] not in ('main_ops','aux_ops') or not isinstance(payload,dict) or set(payload)!={'op_key','payload'}):
                raise ValueError('protected ledger historical record is invalid')
            key=row['api']+'/'+payload.get('op_key','')
            try: ident=_canonical_id(row.get('id'))
            except ValueError as exc: raise ValueError('protected ledger historical record is invalid') from exc
            if (not isinstance(payload.get('op_key'),str) or not re.fullmatch(r'd1-[A-Za-z0-9-]{1,125}',payload['op_key'])
                    or not isinstance(payload.get('payload'),str) or len(payload['payload'])>4096
                    or type(row.get('time_ns')) is not int or row['time_ns']<=0
                    or key in seen_keys or ident in seen_ids):
                raise ValueError('protected ledger historical record is invalid')
            seen_keys.add(key); seen_ids.add(ident)
        elif set(row)=={'event','retained_refresh','revoked_refresh','retained_expected'} and row.get('event')=='historical_auth':
            pair=(row.get('retained_refresh'),row.get('revoked_refresh'))
            if (not all(type(row[k]) is str and row[k] for k in ('retained_refresh','revoked_refresh'))
                    or row['retained_expected'] not in ('accepted','denied') or pair in auth_pairs):
                raise ValueError('protected ledger historical auth is invalid')
            auth_pairs.add(pair)
        else: raise ValueError('protected ledger historical frame is invalid')
        index += 1
    return rows

def _load_input(path, root):
    """Load the exact D3 recovery input contract.

    The private JSON object has exactly INPUT_FIELDS. source_config is the verbatim
    pre-fault B node config object and source_replica its Litestream text. The three
    ledger/report fields are absolute paths below root. producer_unit is exactly
    hat-d3-client-<32 lowercase hex>.service and producer_cgroup is that unit's
    system.slice cgroup. No field is a command, URL, fence action, or recovery override.
    """
    value = _json(_owned_bytes(path, MAX_INPUT))
    if not isinstance(value, dict) or set(value) != INPUT_FIELDS:
        raise ValueError('invalid recovery input fields')
    if (not isinstance(value['authority_operation'], str) or not _OPERATION.fullmatch(value['authority_operation'])
            or not isinstance(value['source_epoch'], str) or not _EPOCH.fullmatch(value['source_epoch'])
            or not isinstance(value['candidate_epoch'], str) or not _EPOCH.fullmatch(value['candidate_epoch'])
            or value['candidate_epoch'] == value['source_epoch']
            or any(not isinstance(value[name], str) or not value[name]
                   for name in ('source_boot', 'candidate_boot'))):
        raise ValueError('invalid recovery authority, epoch, or boot binding')
    _source_config(value['source_config'], value['source_epoch'])
    _replica_config(value['source_replica'], value['source_epoch'])
    match = _PRODUCER.fullmatch(value['producer_unit']) if isinstance(value['producer_unit'], str) else None
    expected_cgroup = '/sys/fs/cgroup/system.slice/' + value['producer_unit'] if match else None
    if not match or value['producer_cgroup'] != expected_cgroup:
        raise ValueError('producer unit or cgroup is not the fixed D3 producer')
    for name in ('protected_ledger', 'protected_baseline', 'fault_ledger'):
        if not isinstance(value[name], str) or not Path(value[name]).is_absolute():
            raise ValueError('artifact paths must be absolute')
        _owned_bytes(value[name], MAX_ARTIFACT, root)
    protected_raw = _owned_bytes(value['protected_ledger'], MAX_ARTIFACT, root)
    _protected_ledger(protected_raw)
    baseline = _cut_report(_json(_owned_bytes(value['protected_baseline'], MAX_INPUT, root)), value['source_epoch'])
    health = value['source_health']
    if (not isinstance(health, dict) or set(health) != {'authority_operation', 'observed_ns', 'probe'}
            or health['authority_operation'] != value['authority_operation']):
        raise ValueError('pre-fault health authority differs')
    probe = _writer(health['probe'], value['source_epoch'], value['source_boot'], value['source_config'])
    start = _json(_owned_bytes(value['fault_ledger'], MAX_ARTIFACT, root).splitlines()[0])
    if (probe['config'] != value['source_config'] or probe.get('replica_config') != value['source_replica']
            or any(probe['status']['positions'][db] < baseline['request']['positions'][db] for db in node.DBS)
            or type(health['observed_ns']) is not int or type(start.get('time_ns')) is not int
            or start.get('event') != 'start' or not 0 <= health['observed_ns'] <= start['time_ns']):
        raise ValueError('source health is not bound before fault traffic at the protected baseline')
    return value, baseline


def _producer_proof(value, unit):
    if (not isinstance(value, dict) or value.get('unit') != unit or value.get('load_state') != 'loaded'
            or value.get('main_pid') != 0 or value.get('active_state') not in ('inactive', 'failed')
            or value.get('cgroup') not in ('absent', 'empty')):
        raise RuntimeError('fault producer death is not independently proven')
    return value


def _fault_outcomes(value, events):
    categories = {'recovered', 'lost', 'ambiguous', 'unacknowledged_recovered', 'rejected'}
    if (not isinstance(value, dict) or set(value) != categories
            or any(not isinstance(rows, list) or any(not isinstance(row, str)
                   or not re.fullmatch(r'(?:main|aux)_ops/d3-[A-Za-z0-9-]{1,125}', row) for row in rows)
                   for rows in value.values())):
        raise ValueError('fault outcome classification is malformed')
    flattened = [row for rows in value.values() for row in rows]
    expected = {event['api'] + '/' + event['row']['op_key']
                for event in events if event['event'] == 'submitted'}
    if len(flattened) != len(set(flattened)) or set(flattened) != expected:
        raise ValueError('fault outcome classifications overlap or omit operations')
    if value['lost']:
        raise RuntimeError('acknowledged writes are missing from the recovery image')
    return value


def _oracle_identity(source, support, binaries):
    support, binaries = Path(support), Path(binaries)

    def trusted_files(root, names):
        # The configured roots and every directory below them remain owned by the
        # controller and non-writable by the oracle account that consumes the files.
        try:
            for directory in (root, *root.parents):
                item = directory.lstat()
                if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                        or item.st_uid not in (0, os.geteuid()) or item.st_mode & 0o022):
                    raise ValueError('oracle trust ancestry is writable, symlinked, or unowned')
            for relative in names:
                path = root / relative
                path.relative_to(root)
                directories = [root]
                directory = root
                for part in path.parent.relative_to(root).parts:
                    directory /= part
                    directories.append(directory)
                for directory in dict.fromkeys(directories):
                    item = directory.lstat()
                    if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                            or item.st_uid != os.geteuid() or item.st_mode & 0o022):
                        raise ValueError('oracle trust directory is writable or unowned')
                item = path.lstat()
                if (not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode)
                        or item.st_uid != os.geteuid() or item.st_mode & 0o022 or item.st_nlink != 1):
                    raise ValueError('oracle trust file is writable, linked, or unowned')
        except OSError as exc:
            raise ValueError('oracle trust boundary is unavailable') from exc

    trusted_files(support, source['support'])
    trusted_files(binaries, source['binaries'])
    authorities = []
    try:
        trusted = {0, os.geteuid()}
        for root, names, error in ((support, source['support'], 'oracle support identity differs'),
                                   (binaries, source['binaries'], 'oracle binary identity differs from captured writer')):
            authorities.append(descriptor.DescriptorAuthority.open_directory(
                root, trusted_root='/', trusted_uids=trusted))
            for name, digest in names.items():
                authority = descriptor.DescriptorAuthority.open_file(
                    root / name, trusted_root='/', trusted_uids=trusted,
                    expected_uid=os.geteuid(), expected_nlink=1,
                    expected_sha256=digest, limit=128 << 20)
                authorities.append(authority)
                if authority.sha256 != digest:
                    raise RuntimeError(error)
        for authority in authorities:
            authority.recheck()
    finally:
        for authority in reversed(authorities):
            authority.close()


def _cold(value, operation, epoch, boot, role, source, replica):
    if (not isinstance(value, dict) or value.get('operation') != operation or value.get('epoch') != epoch
            or value.get('boot_id') != boot or value.get('authority') != 'absent'
            or value.get('cgroup') != 'empty' or value.get('mutators') != 'none'):
        raise RuntimeError('candidate cold identity or safety differs')
    config = value.get('config')
    if (not isinstance(config, dict) or config.get('role') != role or config.get('epoch') != epoch
            or config.get('binaries') != source['binaries'] or config.get('support') != source['support']
            or value.get('replica_config') != replica):
        raise RuntimeError('candidate config, release, support, or replica identity differs')
    return value


def _writer(value, epoch, boot, source):
    from transition import validate_cut
    if (not isinstance(value, dict) or value.get('boot_id') != boot
            or value.get('config', {}).get('role') != 'writer'
            or value.get('config', {}).get('epoch') != epoch
            or value['config'].get('binaries') != source['binaries']
            or value['config'].get('support') != source['support']):
        raise RuntimeError('activated candidate identity differs')
    status = value.get('status', {})
    if (status.get('epoch') != epoch or status.get('healthy') is not True
            or status.get('trailbase_running') is not True):
        raise RuntimeError('activated candidate is not a healthy writer')
    validate_cut(status.get('positions'))
    return value


def _seal_fault(root, input_value, raw):
    run_id = _PRODUCER.fullmatch(input_value['producer_unit']).group(1)
    intake = Path(root) / ('recovery-intake-' + run_id)
    intake.mkdir(mode=0o700)
    sealed = intake / 'fault-ledger.jsonl'
    _write_private(sealed, raw)
    seal = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'source_epoch': input_value['source_epoch'], 'producer_unit': input_value['producer_unit']}
    _write_json(intake / 'fault-seal.json', seal)
    return intake, sealed, seal


def _recheck_fault(input_value, root, sealed, seal):
    raw = _owned_bytes(input_value['fault_ledger'], MAX_ARTIFACT, root)
    copy = _owned_bytes(sealed, MAX_ARTIFACT, root)
    if (len(raw) != seal['bytes'] or raw != copy
            or hashlib.sha256(raw).hexdigest() != seal['sha256']):
        raise RuntimeError('fault ledger changed after sealing')
    client.read_closed_ledger(input_value['fault_ledger'], input_value['source_epoch'])
    return seal['sha256']


def recover(config, *, control_module=None, io_factory=None,
            root=Path('/var/lib/hat-control'),
            input_path=Path('/etc/hat-control/recovery-input.json'),
            maintenance=Path('/etc/hat-control/maintenance'),
            ingress=Path('/etc/hat-ingress/haproxy.cfg'),
            credentials=Path('/etc/hat-control/demo-login.json'),
            oracle_support=Path('/var/lib/hat-oracle/support'),
            oracle_binaries=Path('/opt/hat-oracle/bin')):
    """Recover externally fenced B onto cold A, then pause before the rejoin tail.

    This has no power-off, retry, resume, force, replay, or finish path. The returned
    operation ID is the only identifier a later, separately implemented rejoin may use.
    """
    if control_module is None:
        import control as control_module
    if io_factory is None: io_factory = control_module.ControlIO
    from transition import atomic_json, replace_replica_prefix, validate_cut

    root, input_path, maintenance, ingress = map(Path, (root, input_path, maintenance, ingress))
    with control_module.Journal(root) as journal:
        authority = control_module.current_writer(journal, ingress)  # Must precede begin().
        input_value, protected = _load_input(input_path, root)
        if authority != {'operation': input_value['authority_operation'], 'writer': 'B',
                         'epoch': input_value['source_epoch']}:
            raise RuntimeError('captured source does not match current writer authority and route')
        # D2's completed preflight is the only retained source-boot attestation;
        # provider receipts cannot attest the guest boot incarnation.
        row = journal.db.execute(
            "SELECT evidence FROM steps WHERE operation=? AND phase='preflight' AND status='done'",
            (authority['operation'],)).fetchone()
        try:
            d2_preflight = json.loads(row[0])
            if input_value['source_boot'] != d2_preflight['candidate_boot']:
                raise RuntimeError('captured source boot differs from completed D2 evidence')
        except (TypeError, KeyError, ValueError, IndexError) as exc:
            raise RuntimeError('completed D2 source boot evidence is unavailable') from exc
        if maintenance.exists() or maintenance.is_symlink():
            raise RuntimeError('ingress maintenance already set')
        fault_raw = _owned_bytes(input_value['fault_ledger'], MAX_ARTIFACT, root)
        events = client.read_closed_ledger(input_value['fault_ledger'], input_value['source_epoch'])
        intake, sealed_fault, seal = _seal_fault(root, input_value, fault_raw)
        provisional = {'id': authority['operation'], 'source': 'B', 'target': 'A',
                       'source_epoch': authority['epoch']}
        state = {'ingress_touched': False, 'A': {'boot_id': input_value['candidate_boot'], 'epoch': input_value['candidate_epoch']}}
        guard_io = io_factory(journal, config, provisional, intake, state, maintenance, ingress)
        death = _producer_proof(guard_io.producer_stopped(input_value['producer_unit'],
                                                         input_value['producer_cgroup']),
                                input_value['producer_unit'])
        operation = journal.begin('B', 'A', input_value['source_epoch'])
        if operation['new_epoch'] == input_value['source_epoch']:
            raise RuntimeError('recovery epoch was not freshly reserved')
        work = root / operation['id']
        intake.rename(work)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        sealed_fault = work / sealed_fault.name
        state['events'] = events
        io = io_factory(journal, config, operation, work, state, maintenance, ingress)

        def preflight():
            if socket.gethostname() != config['hostname']: raise ValueError('wrong controller')
            if maintenance.exists() or maintenance.is_symlink(): raise RuntimeError('ingress maintenance already set')
            candidate = io.remote('A', 'inspect-cold')
            expected_replica = replace_replica_prefix(candidate.get('replica_config', ''),
                                                      input_value['candidate_epoch'], input_value['source_epoch'])
            if expected_replica != input_value['source_replica']:
                raise RuntimeError('candidate replica identity differs from captured writer')
            _cold(candidate, operation['id'], input_value['candidate_epoch'], input_value['candidate_boot'],
                  'writer', input_value['source_config'], candidate['replica_config'])
            _oracle_identity(input_value['source_config'], oracle_support, oracle_binaries)
            ledger_authority = io.capture_protected_authority(
                input_value['protected_ledger'], 'd3-recovery-input',
                input_value['source_config']['support'], input_value['source_config']['binaries'])
            control_module.route_to(ingress.read_text(), 'B', 'A', control_module.ROUTE_ENDPOINTS)
            _write_private(work / 'ingress-before.cfg', ingress.read_bytes())
            state['candidate'] = candidate
            return {'authority_operation': authority['operation'], 'source_epoch': authority['epoch'],
                    'source_boot': input_value['source_boot'], 'candidate_boot': input_value['candidate_boot'],
                    'candidate_epoch': input_value['candidate_epoch'], 'producer': death,
                    'fault_ledger_sha256': seal['sha256'], 'protected_baseline': protected,
                    'source_health': input_value['source_health'], 'ledger_authority': ledger_authority}

        def close_ingress():
            return io.close_ingress()

        def fence():
            state['fence'] = io.fence('inspect', 'offline', label='B')
            return state['fence']

        def select_cut():
            selected = io.select_cut(input_value['source_replica'], protected['request']['positions'])
            if not isinstance(selected, dict): raise RuntimeError('restore plan result is malformed')
            validate_cut(selected.get('positions'))
            if any(selected['positions'][db] < protected['request']['positions'][db] for db in node.DBS):
                raise RuntimeError('selected cut is older than protected baseline')
            state['cut'] = selected['positions']
            return selected

        def restore():
            prepared = io.remote('A', 'prepare-recovery', {'source_epoch': operation['source_epoch']})
            if (prepared.get('operation') != operation['id'] or prepared.get('original_epoch') != input_value['candidate_epoch']
                    or prepared.get('original_boot_id') != input_value['candidate_boot']
                    or prepared.get('epoch') != operation['source_epoch'] or prepared.get('role') != 'standby'):
                raise RuntimeError('candidate recovery preparation differs')
            state['A']['epoch'] = operation['source_epoch']
            digest = hashlib.sha256(json.dumps(state['fence'], sort_keys=True).encode()).hexdigest()
            restored = io.remote('A', 'restore-recovery', {'cut': state['cut'], 'fence_digest': digest})
            validate_cut(restored.get('cut'))
            signature = restored.get('signature')
            if (restored.get('operation') != operation['id'] or restored['cut'] != state['cut']
                    or restored.get('original_epoch') != input_value['candidate_epoch']
                    or restored.get('original_boot_id') != input_value['candidate_boot']
                    or restored.get('epoch') != operation['source_epoch']
                    or restored.get('source_epoch') != operation['source_epoch']
                    or restored.get('fence_digest') != digest or not isinstance(signature, dict)
                    or set(signature) != set(node.DBS)
                    or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in signature.values())):
                raise RuntimeError('candidate restored cut or binding differs')
            state['restore'] = restored
            state['fence_digest'] = digest
            return restored

        def compare():
            compared = io.oracle('compare', input_value['source_replica'], state['cut'],
                                 Path(input_value['protected_ledger']), fault_ledger=sealed_fault)
            _cut_report(compared)
            if compared['request']['positions'] != state['cut'] or compared['signature'] != state['restore']['signature']:
                raise RuntimeError('candidate and independent restored images differ')
            _fault_outcomes(compared['checks'].get('fault_outcomes'), state['events'])
            state['comparison'] = compared
            return compared

        def activate():
            _recheck_fault(input_value, root, sealed_fault, seal)
            producer = _producer_proof(io.producer_stopped(input_value['producer_unit'],
                                                           input_value['producer_cgroup']),
                                       input_value['producer_unit'])
            fresh_fence = io.fence('inspect', 'offline', label='B')
            current = io.remote('A', 'inspect-cold')
            _cold(current, operation['id'], operation['source_epoch'], input_value['candidate_boot'],
                  'standby', input_value['source_config'], input_value['source_replica'])
            prepared = io.remote('A', 'prepare', {'new_epoch': operation['new_epoch'],
                                 'signature': state['comparison']['signature'],
                                 'fence_digest': state['fence_digest']})
            if (prepared.get('epoch') != operation['new_epoch']
                    or prepared.get('signature') != state['comparison']['signature']
                    or prepared.get('fence_digest') != state['fence_digest']):
                raise RuntimeError('candidate activation preparation differs')
            state['A']['epoch'] = operation['new_epoch']
            activated = io.remote('A', 'activate-new')
            writer = _writer(io.remote('A', 'probe-new'),
                             operation['new_epoch'], input_value['candidate_boot'], input_value['source_config'])
            state['new'] = writer
            return {'producer': producer, 'source_fence': fresh_fence,
                    'prepare': prepared, 'activate': activated, 'probe': writer}

        def baseline():
            status = state['new']['status']
            report = io.oracle('baseline', state['new']['replica_config'], status['positions'],
                               Path(input_value['protected_ledger']))
            _cut_report(report, operation['new_epoch'])
            if report['request']['positions'] != status['positions']:
                raise RuntimeError('new-epoch baseline positions differ')
            state['baseline'] = report
            return report

        def route():
            text = control_module.route_to((work / 'ingress-before.cfg').read_text(), 'B', 'A',
                                           control_module.ROUTE_ENDPOINTS)
            candidate = work / 'haproxy.cfg'
            _write_private(candidate, text.encode())
            io.command(['haproxy', '-c', '-f', str(candidate)])
            pending = ingress.with_suffix('.d3-pending')
            with pending.open('x') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(text); stream.flush(); os.fsync(stream.fileno())
            os.replace(pending, ingress)
            directory = os.open(ingress.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
            digest = hashlib.sha256(ingress.read_bytes()).hexdigest()
            io.start_ingress(digest)
            return {'writer': 'A', 'epoch': operation['new_epoch'], 'config_sha': digest}

        def verify():
            io.verify_url(Path(input_value['protected_ledger']))
            _owned_bytes(credentials, MAX_INPUT)
            fresh = work / 'new-writes.jsonl'
            io.smoke_url(Path(credentials), fresh)
            io.authorize_fresh_writes(fresh)
            _owned_bytes(fresh, MAX_ARTIFACT, root)
            deadline = time.monotonic() + 90
            while True:
                writer = _writer(io.remote('A', 'probe-new'),
                                 operation['new_epoch'], input_value['candidate_boot'], input_value['source_config'])
                positions = writer['status']['positions']
                if all(positions[db] > state['baseline']['request']['positions'][db] for db in node.DBS): break
                if time.monotonic() > deadline: raise RuntimeError('new writes were not published beyond baseline')
                time.sleep(1)
            report = io.oracle('new-writes', writer['replica_config'], positions, fresh)
            _cut_report(report)
            if report['request']['positions'] != positions: raise RuntimeError('fresh-write restore positions differ')
            return {'writer': 'A', 'epoch': operation['new_epoch'],
                    'positions': positions, 'new_writes': report}

        actions = (preflight, close_ingress, fence, select_cut, restore,
                   compare, activate, baseline, route, verify)
        try:
            for phase, action in zip(control_module.D3_PHASES[:10], actions):
                journal.step(phase, action)
            evidence = {phase: json.loads(raw) for phase, raw in journal.db.execute(
                "SELECT phase,evidence FROM steps WHERE operation=? AND status='done' ORDER BY position",
                (operation['id'],))}
            control_module._validate_d3_proof(operation, evidence)
            return operation['id']
        except BaseException as exc:
            failure = work / 'failure.json'
            if not failure.exists() and not failure.is_symlink():
                phase = control_module.D3_PHASES[min(journal.next, 9)]
                atomic_json(failure, {'phase': phase, 'error': type(exc).__name__})
            try: io.close_ingress()
            except BaseException: pass
            raise
