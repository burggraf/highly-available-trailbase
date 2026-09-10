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
    def module(self):
        self.assertTrue(ENTRY.is_file(),'missing D3 recovery contracts')
        sys.path.insert(0,str(ENTRY.parent))
        spec=importlib.util.spec_from_file_location('hat_recovery',ENTRY)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

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
                   'ledger':{'path':'/var/lib/hat-demo/ledger.jsonl','device':1,'inode':2,'mode':384,'uid':0,'links':1,'bytes':10,'sha256':'a'*64},
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
        self.assertNotIn('payload-value',m.canonical_json(request).decode())
        for patch in ({'profile':'baseline'},{'epoch':'d1-wrong'},{'operation':'b'*32},
                      {'positions':request['positions']|{'main':True}},
                      {'inputs':request['inputs']|{'extra':1}}):
            with self.assertRaises(ValueError):m.validate_acceptance_request(request|patch,operation)

    def test_acceptance_phase_matrix_and_result_are_exact(self):
        m=self.module(); operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        self.assertEqual(m.derive_restore_profile(operation,'compare',False),('comparison','d1-source',5))
        self.assertEqual(m.derive_restore_profile(operation,'baseline',False),('baseline','d1-'+'a'*32,7))
        for phase,fault in (('compare',True),('reconciled-compare',False),('bogus',False)):
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
        self.assertEqual(m.validate_fault_outcomes({k:[] for k in ('recovered','lost','ambiguous','unacknowledged_recovered','rejected')},[]),
                         {k:[] for k in ('recovered','lost','ambiguous','unacknowledged_recovered','rejected')})

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

    def test_raw_canonical_parsers_and_nested_malformed_values_refuse(self):
        m=self.module()
        value={'a':1}
        self.assertEqual(m.parse_canonical_json(m.canonical_json(value)),value)
        for raw in (b'{"a":1,"a":2}',b'{ "a": 1}',b'\xff'):
            with self.assertRaises(ValueError):m.parse_canonical_json(raw)
        operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        bad={'schema':'hat-restore-input-authority-1','operation':operation['id'],'origin':'d2-preflight','ledger':None,'support':None,'binaries':None}
        with self.assertRaises(ValueError):m.validate_acceptance_request({'schema':'x'},operation)
        for epoch in ('d1-', 'd1-'+'x'*126, True):
            with self.assertRaises(ValueError):m.derive_restore_profile(operation|{'source_epoch':epoch},'compare',False)
        with self.assertRaises(ValueError):m.fault_operations([{'event':'garbage'}])
        with self.assertRaises(ValueError):m.validate_fault_outcomes({'recovered':[],'lost':[],'ambiguous':[],'unacknowledged_recovered':[],'rejected':[]},[{'event':'garbage'}])

    def test_acceptance_result_rejects_legacy_and_mismatch(self):
        m=self.module(); operation={'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        request={'schema':'hat-restore-acceptance-1','operation':operation['id'],'phase':'compare','source':'A','target':'B','epoch':'d1-source','positions':{'main':1,'session':1,'aux':1},'profile':'comparison','inputs':{}}
        db={name:{'position':1,'sha256':'a'*64,'integrity':'PASS','foreign_keys':'PASS'} for name in ('main','session','aux')}
        result={'schema':'hat-restore-acceptance-1','request':request,'request_sha256':'x'*64,'databases':db,'signature':{name:'b'*64 for name in ('main','session','aux')},'checks':{'records':'PASS','authentication':'PASS'}}
        with self.assertRaises(ValueError):m.validate_acceptance_result(result,request)
        with self.assertRaises(ValueError):m.validate_acceptance_result(result|{'auth_and_records':'PASS'},request)

if __name__=='__main__':unittest.main()
