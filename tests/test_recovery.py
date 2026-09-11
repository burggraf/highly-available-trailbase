"""D3 cut and outcome contracts; no providers, live services or experiment runner."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ENTRY=Path(os.environ.get('HAT_RECOVERY_ENTRY',str(Path(__file__).resolve().parents[1]/'hat/recovery.py')))

class RecoveryTests(unittest.TestCase):
    def _authority(self, operation, origin):
        support={name:'b'*64 for name in ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')}
        ledger_operation = (('0' if operation['id'] != '0'*32 else '1')*32
                            if origin == 'd3-recovery-input' else operation['id'])
        return {'schema':'hat-restore-input-authority-1','operation':operation['id'],'origin':origin,
                'ledger':{'path':'/var/lib/hat-control/'+ledger_operation+'/'+('new-writes.jsonl' if origin=='current-verify-exclusive' else 'ledger.jsonl'),'device':1,'inode':2,'mode':384,'uid':0,'links':1,'bytes':10,'sha256':'a'*64},'support':support,'binaries':{'trail':'c'*64,'litestream':'d'*64}}
    def _request(self, operation, phase, authority):
        profile,epoch,_,_=self.module().derive_restore_profile(operation,phase,phase=='compare' and operation['source']=='B')
        inputs={'replica_config_sha256':'e'*64,'ledger_sha256':'a'*64,'ledger_authority':authority,'restore_points':{db:{'source':'/var/lib/hat-demo/depot/data/'+db+'.db','position':1} for db in ('main','session','aux')},'support':authority['support'],'binaries':authority['binaries']}
        if profile=='recovery-comparison':
            ops=['main_ops/d3-a']; inputs.update(fault_ledger_sha256='f'*64,fault_operations=ops,fault_operation_count=1,fault_operations_sha256=__import__('hashlib').sha256(self.module().canonical_json(ops)).hexdigest())
        return {'schema':'hat-restore-acceptance-1','operation':operation['id'],'phase':phase,'source':operation['source'],'target':operation['target'],'epoch':epoch,'positions':{db:1 for db in ('main','session','aux')},'profile':profile,'inputs':inputs}

    def module(self):
        self.assertTrue(ENTRY.is_file(),'missing D3 recovery contracts')
        sys.path.insert(0,str(ENTRY.parent))
        spec=importlib.util.spec_from_file_location('hat_recovery',ENTRY)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

    def test_parser_and_timestamp_errors_do_not_leak_attacker_text(self):
        m=self.module(); marker='SECRET_TIMESTAMP_MARKER'
        plan=dict(source='/source/main.db',target_path='/fresh/main.db',replica='s3',min_txid='0000000000000001',max_txid='0000000000000003',files=[dict(level=9,name='0000000000000001-0000000000000003.ltx',min_txid='0000000000000001',max_txid='0000000000000003',size=4096,timestamp=marker)])
        with self.assertRaises(ValueError) as caught:m.restore_endpoint(plan,'/source/main.db','/fresh/main.db',2)
        chain=[]; cur=caught.exception
        while cur: chain += [str(cur)]; cur=cur.__cause__ or cur.__context__
        self.assertTrue(all(marker not in text for text in chain))
        start={'event':'start','run_id':'d3-'+'a'*32,'source_epoch':'d1-source','time_ns':1,'utc':marker}
        with self.assertRaises(ValueError) as caught:m.fault_operations([start,{'event':'stop','submitted':0,'acknowledged':0,'rejected':0,'uncertain':0,'time_ns':2,'utc':'2026-01-01T00:00:01Z'}])
        self.assertNotIn(marker,str(caught.exception)); self.assertIsNone(caught.exception.__cause__)

    def test_canonical_parser_measures_structure_not_raw_delimiters(self):
        m=self.module()
        for value in ({'text':'many } [ ] \\" \\\\ delimiters'}, {'items':['[']*1000}, {'close':'}'}):
            raw=m.canonical_json(value)
            self.assertEqual(m.parse_canonical_json(raw),value)
        deep=[]; current=deep
        for _ in range(513): current.append([]); current=current[0]
        with self.assertRaises(ValueError) as caught:m.parse_canonical_json(m.canonical_json(deep))
        self.assertNotIn('SECRET',str(caught.exception)); self.assertIsNone(caught.exception.__cause__)
        for raw in (b'', b'{}'*(1<<20)):
            with self.assertRaises(ValueError):m.parse_canonical_json(raw)

    def test_restore_plan_is_exact_bounded_and_not_older_than_baseline(self):
        m=self.module()
        plan=dict(source='/source/main.db',target_path='/fresh/main.db',replica='s3',min_txid='0000000000000001',max_txid='0000000000000003',files=[dict(level=9,name='0000000000000001-0000000000000003.ltx',min_txid='0000000000000001',max_txid='0000000000000003',size=4096,timestamp='2026-09-08T00:00:00Z')])
        self.assertEqual(m.restore_endpoint(plan,'/source/main.db','/fresh/main.db',2),3)
        for patch in ({'source':'/wrong.db'},{'target_path':'/existing.db'},{'replica':'file'},{'extra':True},{'max_txid':'bad'},{'files':[]}):
            with self.assertRaises(ValueError):m.restore_endpoint(plan|patch,'/source/main.db','/fresh/main.db',2)
        with self.assertRaises(ValueError):m.restore_endpoint(plan,'/source/main.db','/fresh/main.db',4)
        for patch in ({'size':True},{'level':10},{'name':'../escape.ltx'},{'timestamp':'no-timezone'},{'unexpected':1}):
            with self.assertRaises(ValueError):m.restore_endpoint(plan|{'files':[plan['files'][0]|patch]},'/source/main.db','/fresh/main.db',2)

    def test_fault_outcomes_do_not_turn_uncertainty_into_proven_loss(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            for db in ('main','aux'):
                with sqlite3.connect(root/(db+'.db')) as conn:
                    conn.execute('CREATE TABLE hat_ops(id INTEGER PRIMARY KEY,op_key TEXT UNIQUE,payload TEXT)')
                    conn.execute('INSERT INTO hat_ops VALUES(1,?,?)',('d3-'+db,'value'))
            def event(kind,api,key,**extra):return dict(event=kind,api=api,row=dict(op_key=key,payload='value'),**extra)
            events=[event('submitted','main_ops','d3-main'),event('acknowledged','main_ops','d3-main',id='1'),
                    event('submitted','aux_ops','d3-lost'),event('acknowledged','aux_ops','d3-lost',id='2'),
                    event('submitted','main_ops','d3-unknown'),event('uncertain','main_ops','d3-unknown'),
                    event('submitted','aux_ops','d3-aux'),event('uncertain','aux_ops','d3-aux'),
                    event('submitted','main_ops','d3-reject'),event('rejected','main_ops','d3-reject')]
            value=m.classify_fault(events,root)
            self.assertEqual(value,dict(recovered=['main_ops/d3-main'],lost=['aux_ops/d3-lost'],ambiguous=['main_ops/d3-unknown'],unacknowledged_recovered=['aux_ops/d3-aux'],rejected=['main_ops/d3-reject']))
            for bad in ([events[1]],events+[events[1]],events+[events[0]]):
                with self.assertRaises(ValueError):m.classify_fault(bad,root)
            changed=json.loads(json.dumps(events));changed[1]['row']['payload']='wrong'
            with self.assertRaises(ValueError):m.classify_fault(changed,root)
            with sqlite3.connect(root/'main.db') as conn:conn.execute("UPDATE hat_ops SET payload='corrupt'")
            with self.assertRaises(ValueError):m.classify_fault(events,root)

    def test_acceptance_request_contract_is_canonical_and_bound(self):
        m=self.module()
        operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        authority={'schema':'hat-restore-input-authority-1','operation':operation['id'],'origin':'d2-preflight',
                   'ledger':{'path':'/var/lib/hat-control/'+operation['id']+'/'+'ledger.jsonl','device':1,'inode':2,'mode':384,'uid':0,'links':1,'bytes':10,'sha256':'a'*64},
                   'support':{name:'b'*64 for name in ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')},
                   'binaries':{'trail':'c'*64,'litestream':'d'*64}}
        request={'schema':'hat-restore-acceptance-1','operation':operation['id'],'phase':'compare','source':'A','target':'B',
                 'epoch':'d1-source','positions':{'main':1,'session':2,'aux':3},'profile':'comparison',
                 'inputs':{'replica_config_sha256':'e'*64,'ledger_sha256':'a'*64,'ledger_authority':authority,
                           'restore_points':{db:{'source':'/var/lib/hat-demo/depot/data/'+db+'.db','position':pos} for db,pos in zip(('main','session','aux'),(1,2,3))},
                           'support':authority['support'],'binaries':authority['binaries']}}
        raw=m.canonical_json(request)
        self.assertEqual(raw,m.canonical_json(json.loads(raw)))
        self.assertEqual(m.validate_acceptance_request(request,operation),request)
        self.assertEqual(m.parse_acceptance_request(raw,operation),request)
        for extra in ('fault_ledger_sha256', 'arbitrary'):
            changed=json.loads(json.dumps(request)); changed['inputs'][extra]='f'*64
            with self.assertRaises(ValueError): m.validate_acceptance_request(changed,operation)
            with self.assertRaises(ValueError): m.parse_acceptance_request(m.canonical_json(changed),operation)
        self.assertNotIn('payload-value',m.canonical_json(request).decode())

    def test_replica_config_and_authority_mapping_are_strict(self):
        m=self.module(); operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        good='path: demos/d1-source/main\n  path: demos/d1-source/session # comment\n\tpath: demos/d1-source/aux\n  comment: value\n'
        self.assertEqual(m._replica_config(good.encode(), 'd1-source'), good.encode())
        for raw in (b'',good.encode().replace(b'\n',b'\r\n'),b'\xef\xbb\xbf'+good.encode(),good.encode()+b'\x00',good.encode().replace(b'demos/d1-source/aux',b'demos/d1-source/other')):
            with self.assertRaises(ValueError):m._replica_config(raw,'d1-source')
        auth=self._authority(operation,'d2-preflight')
        self.assertEqual(m.validate_acceptance_request(self._request(operation,'compare',auth),operation)['profile'],'comparison')
        for origin,phase in (('d3-recovery-input','compare'),('current-verify-exclusive','baseline')):
            bad=self._request(operation,phase,self._authority(operation,origin))
            with self.assertRaises(ValueError):m.validate_acceptance_request(bad,operation)

    def test_d3_authority_accepts_only_canonical_prior_operation_ledger(self):
        m=self.module(); current='b'*32; prior='a'*32
        operation={'id':current,'source':'B','target':'A','source_epoch':'d1-source','new_epoch':'d1-'+current}
        authority=self._authority(operation,'d3-recovery-input')
        authority['ledger']['path']='/var/lib/hat-control/'+prior+'/ledger.jsonl'
        self.assertEqual(m.validate_acceptance_request(self._request(operation,'compare',authority),operation)['inputs']['ledger_authority'],authority)
        for path in ('/var/lib/hat-control/'+current+'/ledger.jsonl',
                     '/var/lib/hat-control/'+prior+'/other.jsonl',
                     '/var/lib/hat-control/../outside/ledger.jsonl',
                     '/tmp/'+prior+'/ledger.jsonl'):
            bad=json.loads(json.dumps(authority)); bad['ledger']['path']=path
            with self.assertRaises(ValueError):m.validate_acceptance_request(self._request(operation,'compare',bad),operation)


    def test_acceptance_phase_matrix_and_result_are_exact(self):
        m=self.module(); operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        self.assertEqual(m.derive_restore_profile(operation,'compare',False),('comparison','d1-source',5,False))
        self.assertEqual(m.derive_restore_profile(operation,'baseline',False),('baseline','d1-'+'a'*32,7,False))
        self.assertEqual(m.derive_restore_profile(operation,'reconciled-compare',False),('comparison','d1-source',5,True))
        self.assertEqual(m.derive_restore_profile(operation,'verification-baseline',False),('baseline','d1-'+'a'*32,9,True))
        for phase,fault in (('compare',True),('verification-baseline',True),('bogus',False)):
            with self.assertRaises(ValueError):m.derive_restore_profile(operation,phase,fault)
        with self.assertRaises(ValueError):m.derive_restore_profile({'id':'b'*32,'source':'B','target':'A','source_epoch':'d1-s','new_epoch':'d1-'+('b'*32)},'compare',False)

    def test_fault_submitted_set_and_zero_loss_contract(self):
        m=self.module()
        events=[{'event':'start','run_id':'d3-'+'a'*32,'source_epoch':'d1-source','time_ns':1,'utc':'2026-01-01T00:00:00Z'},
                {'event':'submitted','api':'main_ops','row':{'op_key':'d3-a','payload':'x'},'time_ns':2},
                {'event':'acknowledged','api':'main_ops','row':{'op_key':'d3-a','payload':'x'},'id':'1','time_ns':3},
                {'event':'stop','submitted':1,'acknowledged':1,'rejected':0,'uncertain':0,'time_ns':4,'utc':'2026-01-01T00:00:01Z'}]
        self.assertEqual(m.fault_operations(events),['main_ops/d3-a'])
        result={'recovered':['main_ops/d3-a'],'lost':[],'ambiguous':[],'unacknowledged_recovered':[],'rejected':[]}
        self.assertEqual(m.validate_fault_outcomes(result,events),result)
        for bad in (result|{'lost':['main_ops/d3-a']},result|{'recovered':[]},result|{'extra':[]}):
            with self.assertRaises(ValueError):m.validate_fault_outcomes(bad,events)
        empty_events=[events[0],{'event':'stop','submitted':0,'acknowledged':0,'rejected':0,'uncertain':0,'time_ns':2,'utc':'2026-01-01T00:00:01Z'}]
        empty={k:[] for k in ('recovered','lost','ambiguous','unacknowledged_recovered','rejected')}
        self.assertEqual(m.validate_fault_outcomes(empty,empty_events),empty)
        for bad in (result|{'recovered':[{}]},result|{'recovered':['main_ops/not-d3']},result|{'recovered':[1]}):
            with self.assertRaises(ValueError):m.validate_fault_outcomes(bad,events)

    def test_fault_seal_binds_source_and_copy_descriptor_identity_durably(self):
        m=self.module()
        start={'event':'start','run_id':'d3-'+'a'*32,'source_epoch':'d1-source','time_ns':1,'utc':'2026-01-01T00:00:00Z'}
        stop={'event':'stop','submitted':0,'acknowledged':0,'rejected':0,'uncertain':0,'time_ns':2,'utc':'2026-01-01T00:00:01Z'}
        raw=b''.join(m.canonical_json(row)+b'\n' for row in (start,stop))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); root.chmod(0o700)
            source=root/'fault.jsonl'; source.write_bytes(raw); source.chmod(0o600)
            value={'producer_unit':'hat-d3-client-'+'a'*32+'.service',
                   'source_epoch':'d1-source','fault_ledger':str(source)}
            intake,sealed,seal=m._seal_fault(root,value,raw)
            persisted=json.loads((intake/'fault-seal.json').read_text())
            self.assertEqual(seal,persisted)
            self.assertEqual(m._recheck_fault(value,root,sealed,persisted),seal['sha256'])
            replacement=root/'replacement'; replacement.write_bytes(raw); replacement.chmod(0o600)
            replacement.replace(source)
            with self.assertRaises(RuntimeError): m._recheck_fault(value,root,sealed,persisted)

    def test_fault_seal_rejects_unsafe_owner_mode_link_and_changed_copy_identity(self):
        m=self.module(); raw=b'x\n'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); root.chmod(0o700)
            source=root/'fault.jsonl'; source.write_bytes(raw); source.chmod(0o600)
            value={'producer_unit':'hat-d3-client-'+'a'*32+'.service',
                   'source_epoch':'d1-source','fault_ledger':str(source)}
            linked=root/'linked'; os.link(source,linked)
            with self.assertRaises(ValueError): m._seal_fault(root,value,raw)
            linked.unlink(); source.chmod(0o640)
            with self.assertRaises(ValueError): m._seal_fault(root,value,raw)

    def test_fault_ledger_bounds_ids_times_and_semantics(self):
        m=self.module(); start={'event':'start','run_id':'d3-'+'a'*32,'source_epoch':'d1-source','time_ns':1,'utc':'2026-01-01T00:00:00Z'}
        sub={'event':'submitted','api':'main_ops','row':{'op_key':'d3-a','payload':'x'},'time_ns':2}
        ack={'event':'acknowledged','api':'main_ops','row':sub['row'],'id':'1','time_ns':3}
        stop={'event':'stop','submitted':1,'acknowledged':1,'rejected':0,'uncertain':0,'time_ns':4,'utc':'2026-01-01T00:00:01Z'}
        for patch,index in (({'id':'9223372036854775808'},2),({'time_ns':True},3),({'utc':'bad'},3),({'time_ns':2},2)):
            rows=[start,sub,ack,stop]; rows[index]=rows[index]|patch
            with self.assertRaises(ValueError):m.fault_operations(rows)
        with self.assertRaises(ValueError):m.fault_operations([start]+[sub,ack]*1001+[stop])
        rejected=ack|{'event':'rejected'}; rejected.pop('id')
        events=[start,sub,rejected,stop|{'acknowledged':0,'rejected':1}]
        bad={'recovered':['main_ops/d3-a'],'lost':[],'ambiguous':[],'unacknowledged_recovered':[],'rejected':[]}
        with self.assertRaises(ValueError):m.validate_fault_outcomes(bad,events)

    def test_protected_ledger_future_grammar_is_strict(self):
        m=self.module()
        rows=[{'auth_token':'token','retained_refresh':'keep','revoked_refresh':'drop'},
              {'event':'submitted','api':'main_ops','row':{'op_key':'d1-main','payload':'x'},'time_ns':1},
              {'event':'acknowledged','api':'main_ops','row':{'op_key':'d1-main','payload':'x'},'id':'1','time_ns':2},
              {'event':'submitted','api':'aux_ops','row':{'op_key':'d1-aux','payload':'x'},'time_ns':3},
              {'event':'acknowledged','api':'aux_ops','row':{'op_key':'d1-aux','payload':'x'},'id':'2','time_ns':4},
              {'event':'smoke_pass'},
              {'event':'historical_auth','retained_refresh':'old','revoked_refresh':'gone','retained_expected':'denied'}]
        raw=b''.join(m.canonical_json(row)+b'\n' for row in rows)
        self.assertEqual(len(m._protected_ledger(raw)),len(rows))
        for bad in (raw.replace(b'\n',b'\r\n'),b'\xef\xbb\xbf'+raw,raw.replace(b'd1-main',b'd1-main2')+b'\x00'):
            with self.assertRaises(ValueError):m._protected_ledger(bad)
        with self.assertRaises(ValueError):m._protected_ledger(raw.replace(b'"smoke_pass"',b'"unexpected"'))
        with self.assertRaises(ValueError):m._protected_ledger(raw.replace(b'"id":"1"',b'"id":"9223372036854775808"'))

    def test_raw_canonical_parsers_and_nested_malformed_values_refuse(self):
        m=self.module()
        value={'a':1}
        self.assertEqual(m.parse_canonical_json(m.canonical_json(value)),value)
        for raw in (b'{"a":1,"a":2}',b'{ "a": 1}',b'\xff'):
            with self.assertRaises(ValueError):m.parse_canonical_json(raw)
        with self.assertRaises(ValueError):m.parse_acceptance_request(b'{ "a":1}',{'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32})
        operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        bad={'schema':'hat-restore-input-authority-1','operation':operation['id'],'origin':'d2-preflight','ledger':None,'support':None,'binaries':None}
        with self.assertRaises(ValueError):m.validate_acceptance_request({'schema':'x'},operation)
        for epoch in ('d1-', 'd1-'+'x'*126, True):
            with self.assertRaises(ValueError):m.derive_restore_profile(operation|{'source_epoch':epoch},'compare',False)
        with self.assertRaises(ValueError):m.fault_operations([{'event':'garbage'}])
        with self.assertRaises(ValueError):m.validate_fault_outcomes({'recovered':[],'lost':[],'ambiguous':[],'unacknowledged_recovered':[],'rejected':[]},[{'event':'garbage'}])

    def test_valid_results_bind_original_operation_for_each_profile(self):
        m=self.module()
        for source,target,phase,fault in (('A','B','compare',False),('B','A','compare',True),('A','B','baseline',False),('A','B','new-writes',False)):
            with self.subTest(phase=phase,source=source):
                ident=('a' if source=='A' else 'b')*32
                operation={'id':ident,'source':source,'target':target,'source_epoch':'d1-source','new_epoch':'d1-'+ident}
                profile,epoch,_,_=m.derive_restore_profile(operation,phase,fault)
                support={name:'b'*64 for name in ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')}
                authority={'schema':'hat-restore-input-authority-1','operation':ident,'origin':'current-verify-exclusive' if phase=='new-writes' else ('d2-preflight' if source=='A' else 'd3-recovery-input'),
                           'ledger':{'path':'/var/lib/hat-control/'+(('0'*32) if source=='B' else operation['id'])+'/'+('new-writes.jsonl' if phase=='new-writes' else 'ledger.jsonl'),'device':1,'inode':2,'mode':384,'uid':0,'links':1,'bytes':10,'sha256':'a'*64},
                           'support':support,'binaries':{'trail':'c'*64,'litestream':'d'*64}}
                inputs={'replica_config_sha256':'e'*64,'ledger_sha256':'a'*64,'ledger_authority':authority,
                        'restore_points':{db:{'source':'/var/lib/hat-demo/depot/data/'+db+'.db','position':1} for db in ('main','session','aux')},
                        'support':support,'binaries':authority['binaries']}
                if fault:
                    operations=['main_ops/d3-a'];inputs|={'fault_ledger_sha256':'f'*64,'fault_operations':operations,'fault_operation_count':1,
                                                         'fault_operations_sha256':__import__('hashlib').sha256(m.canonical_json(operations)).hexdigest()}
                request={'schema':'hat-restore-acceptance-1','operation':ident,'phase':phase,'source':source,'target':target,'epoch':epoch,
                         'positions':{db:1 for db in ('main','session','aux')},'profile':profile,'inputs':inputs}
                checks={'records':'PASS','authentication':'PASS'}
                if fault:checks|={'fault_outcomes':{'recovered':['main_ops/d3-a'],'lost':[],'ambiguous':[],'unacknowledged_recovered':[],'rejected':[]},'acknowledged_loss':'NONE'}
                result={'schema':'hat-restore-acceptance-1','request':request,'request_sha256':__import__('hashlib').sha256(m.canonical_json(request)).hexdigest(),
                        'databases':{db:{'position':1,'sha256':'a'*64,'integrity':'PASS','foreign_keys':'PASS'} for db in ('main','session','aux')},
                        'signature':{db:'b'*64 for db in ('main','session','aux')},'checks':checks}
                self.assertEqual(m.validate_acceptance_result(result,request,operation),result)
                self.assertEqual(m.parse_acceptance_result(m.canonical_json(result),request,operation),result)
                with self.assertRaises(ValueError):
                    m.validate_acceptance_result(result | {'databases': result['databases'] | {'main': result['databases']['main'] | {'position': True}}}, request, operation)

    def test_acceptance_result_rejects_legacy_and_mismatch(self):
        m=self.module(); operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        request={'schema':'hat-restore-acceptance-1','operation':operation['id'],'phase':'compare','source':'A','target':'B','epoch':'d1-source','positions':{'main':1,'session':1,'aux':1},'profile':'comparison','inputs':{}}
        db={name:{'position':1,'sha256':'a'*64,'integrity':'PASS','foreign_keys':'PASS'} for name in ('main','session','aux')}
        result={'schema':'hat-restore-acceptance-1','request':request,'request_sha256':'x'*64,'databases':db,'signature':{name:'b'*64 for name in ('main','session','aux')},'checks':{'records':'PASS','authentication':'PASS'}}
        with self.assertRaises(ValueError):m.validate_acceptance_result(result,request,operation)
        with self.assertRaises(ValueError):m.validate_acceptance_result(result|{'auth_and_records':'PASS'},request,operation)
        with self.assertRaises(ValueError):m.parse_acceptance_result(m.canonical_json(result),request,operation)

if __name__=='__main__':unittest.main()
