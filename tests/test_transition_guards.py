"""Fixed D2 request and frozen-data contracts; no SSH/provider calls."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ENTRY = Path(os.environ.get('HAT_TRANSITION_ENTRY', str(Path(__file__).resolve().parents[1]/'hat/transition.py')))

class GuardTests(unittest.TestCase):
    def module(self):
        self.assertTrue(ENTRY.is_file(), 'missing node transition entrypoint')
        sys.path.insert(0, str(ENTRY.parent))
        spec = importlib.util.spec_from_file_location('hat_transition', ENTRY)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_mutations_require_exact_epoch_boot_and_request_shape(self):
        m = self.module(); c = dict(epoch='d1-old', role='writer')
        request = dict(action='quiesce', operation='a'*32, epoch='d1-old', boot_id='boot', payload={})
        m.validate_request(request, c, 'boot')
        for patch in [dict(operation='../escape'), dict(epoch='d1-other'), dict(boot_id='stale'), dict(force=True), dict(action='shell'), dict(payload={'extra':True})]:
            with self.assertRaises(ValueError): m.validate_request(request | patch, c, 'boot')
        with self.assertRaises(ValueError): m.validate_request(request, c | dict(role='standby'), 'boot')

    def test_frozen_inspection_is_boot_bound_and_standby_only(self):
        m=self.module();r=dict(action='inspect-frozen',operation='a'*32,epoch='d1-old',boot_id='boot',payload={})
        c=dict(epoch='d1-old',role='standby')
        try:m.validate_request(r,c,'boot')
        except ValueError:self.fail('missing read-only frozen inspection')
        with self.assertRaises(ValueError):m.validate_request(r,c,'new-boot')
        with self.assertRaises(ValueError):m.validate_request(r,c|{'role':'writer'},'boot')

    def test_cut_is_complete_numeric_and_positive(self):
        m = self.module()
        try:
            m.validate_request(dict(action='restore',operation='a'*32,epoch='d1-old',boot_id='boot',payload={'cut':dict(main=1,session=2,aux=3)}),dict(epoch='d1-old',role='standby'),'boot')
        except ValueError: self.fail('finite-restore fallback request is missing')
        m.validate_cut(dict(main=1,session=2,aux=3))
        for value in [{}, dict(main=1,session=2), dict(main=True,session=2,aux=3), dict(main=0,session=2,aux=3)]:
            with self.assertRaises(ValueError): m.validate_cut(value)

    def test_logical_comparison_covers_auth_and_all_three_databases(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            for name in ('main','session','aux'):
                with sqlite3.connect(root/(name+'.db')) as db:
                    if name != 'session': db.execute('CREATE TABLE hat_ops(id INTEGER,op_key TEXT,payload TEXT)')
                    if name == 'main': db.execute('CREATE TABLE _user(id BLOB)')
                    if name == 'session': db.execute('CREATE TABLE _session(id BLOB)')
            original = m.logical_signature(root)
            self.assertEqual(set(original), {'main','session','aux'})
            with sqlite3.connect(root/'session.db') as db: db.execute("INSERT INTO _session VALUES(x'1234')")
            changed = m.logical_signature(root)
            self.assertNotEqual(original['session'],changed['session'])
            self.assertEqual(original['main'],changed['main'])
            (root/'aux.db').unlink()
            with self.assertRaises(ValueError): m.logical_signature(root)

if __name__ == '__main__': unittest.main()
