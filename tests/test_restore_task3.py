import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
import recovery

class RestoreTask3Tests(unittest.TestCase):
    def test_request_bytes_are_canonical_and_no_positions_file_contract(self):
        op = {'id':'a'*32,'source':'A','target':'B','source_epoch':'d1-source','new_epoch':'d1-'+'a'*32}
        auth={'schema':'hat-restore-input-authority-1','operation':op['id'],'origin':'d2-preflight',
              'ledger':{'path':'/var/lib/hat-control/'+op['id']+'/ledger.jsonl','device':1,'inode':1,'mode':384,'uid':0,'links':1,'bytes':1,'sha256':'a'*64},
              'support':{k:'b'*64 for k in ('config.textproto','migrations/main/U100__hat_ops.sql','migrations/aux/U100__hat_ops.sql','secrets/keys/private_key.pem','secrets/keys/public_key.pem')},
              'binaries':{'trail':'c'*64,'litestream':'d'*64}}
        req={'schema':'hat-restore-acceptance-1','operation':op['id'],'phase':'compare','source':'A','target':'B','epoch':op['source_epoch'],'positions':{'main':1,'session':1,'aux':1},'profile':'comparison',
             'inputs':{'replica_config_sha256':'e'*64,'ledger_sha256':'a'*64,'ledger_authority':auth,'restore_points':{d:{'source':'/var/lib/hat-demo/depot/data/'+d+'.db','position':1} for d in ('main','session','aux')},'support':auth['support'],'binaries':auth['binaries']}}
        raw=recovery.canonical_json(req)
        self.assertEqual(recovery.parse_acceptance_request(raw,op),req)
        self.assertNotIn('positions.json', raw.decode())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), hashlib.sha256(recovery.canonical_json(req)).hexdigest())

if __name__ == '__main__': unittest.main()
