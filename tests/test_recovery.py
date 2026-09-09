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

if __name__=='__main__':unittest.main()
