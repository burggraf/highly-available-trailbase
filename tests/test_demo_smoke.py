"""Historical authentication must not be silently omitted from restore checks."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import demo_smoke

class HistoricalAuthTests(unittest.TestCase):
    def test_historical_retained_and_revoked_tokens_are_checked(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=Path(d)/'ledger.jsonl'
            ledger.write_text(json.dumps(dict(auth_token='fresh',retained_refresh='keep0',revoked_refresh='drop0'))+'\n'+json.dumps(dict(event='historical_auth',retained_refresh='keep1',revoked_refresh='drop1',retained_expected='accepted'))+'\n')
            def response(base,path,method='GET',body=None,token=None):
                return (403 if body['refresh_token'].startswith('drop') or body['refresh_token']=='keep1' else 200), {'auth_token':'renewed'}
            with mock.patch.object(demo_smoke,'request',side_effect=response):
                with self.assertRaises(AssertionError): demo_smoke.verify_restore('unused',ledger)
            checked=[]
            def good(base,path,method='GET',body=None,token=None):
                checked.append(body['refresh_token'])
                return (403 if body['refresh_token'].startswith('drop') else 200), {'auth_token':'renewed'}
            with mock.patch.object(demo_smoke,'request',side_effect=good): demo_smoke.verify_restore('unused',ledger)
            self.assertEqual(set(checked), {'keep0','drop0','keep1','drop1'})

    def test_record_reads_use_renewed_access_token_after_operator_delay(self):
        with tempfile.TemporaryDirectory() as d:
            ledger=Path(d)/'ledger.jsonl'
            ledger.write_text(json.dumps(dict(auth_token='expired',retained_refresh='keep',revoked_refresh='drop'))+'\n'+json.dumps(dict(event='acknowledged',api='main_ops',id=1,row={'op_key':'retained'}))+'\n')
            def response(base,path,method='GET',body=None,token=None):
                if body is not None:return (403 if body['refresh_token']=='drop' else 200),{'auth_token':'renewed'}
                self.assertEqual(token,'renewed')
                return 200,{'op_key':'retained'}
            with mock.patch.object(demo_smoke,'request',side_effect=response):demo_smoke.verify_restore('unused',ledger)

if __name__=='__main__': unittest.main()
