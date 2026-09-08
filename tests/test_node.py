"""Small direct checks; real Linux/systemd checks remain deployment gates."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import hashlib
import sys
import tempfile
import unittest

ENTRY = Path(os.environ.get('HAT_NODE_ENTRY', str(Path(__file__).resolve().parents[1] / 'hat/node.py')))

class NodeTests(unittest.TestCase):
    def load(self):
        self.assertTrue(ENTRY.is_file(), 'operational node entrypoint must exist')
        spec = importlib.util.spec_from_file_location('hat_node_test', ENTRY)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_txid_contract(self):
        m = self.load()
        self.assertEqual(m.txid('000000000000001a'), 26)
        for value in [True, 26, '1a', '-000000000000001', '00000000000000xz']:
            with self.assertRaises(ValueError): m.txid(value)

    def test_sync_contract(self):
        m = self.load()
        raw = dict(db_path='/data/main.db', txid=26, replica_txid=26, duration_ms=12)
        self.assertEqual(m.sync_position(raw, '/data/main.db'), 26)
        for patch in [{'replica_txid': '1a'}, {'replica_txid': True}, {'db_path': '/wrong'}, {'replica_txid': 25}]:
            with self.assertRaises(ValueError): m.sync_position(raw | patch, '/data/main.db')

    def test_status_never_turns_liveness_into_backup_health(self):
        m = self.load()
        state = dict(role='standby', epoch='d1-e1', sampled_at=100, positions={'main': 1, 'session': 2, 'aux': 1}, refusals=[])
        self.assertFalse(m.public_status(state, 140)['healthy'])
        self.assertTrue(m.public_status(state, 101)['healthy'])
        state['positions'].pop('aux')
        self.assertFalse(m.public_status(state, 101)['healthy'])
        state['positions']['aux'] = 1
        state['refusals'] = ['unknown follower log']
        self.assertFalse(m.public_status(state, 101)['healthy'])
        self.assertFalse(m.public_status(state, 101)['promotion_ready'])

    def test_writer_authority_is_boot_bound_and_standby_cannot_activate(self):
        m = self.load()
        valid = dict(role='writer', epoch='d1-e1', boot_id='boot-one')
        self.assertTrue(m.authorized('writer', 'd1-e1', 'boot-one', valid))
        for role, epoch, boot in [('standby','d1-e1','boot-one'), ('writer','d1-e2','boot-one'), ('writer','d1-e1','boot-two')]:
            self.assertFalse(m.authorized(role, epoch, boot, valid))
        self.assertFalse(m.authorized('writer','d1-e1','boot-one',{}))

    def test_log_gate_known_pinned_startup_and_unknown_fail_closed(self):
        m = self.load()
        self.assertFalse(m.log_bad('{"level":"INFO","msg":"litestream","version":"0.5.17","level":""}'))
        for line in ['garbage', '{"msg":"no level"}', '{"level":"INFO","level":"ERROR","msg":"bad"}', '{"level":"ERROR","msg":"restore failed"}']:
            self.assertTrue(m.log_bad(line))

    def test_pinned_real_log_fixture_and_malformed_records(self):
        m = self.load()
        fixture = Path(__file__).parent / 'fixtures/litestream-0.5.17-replicate.jsonl'
        for line in fixture.read_text().splitlines():
            self.assertFalse(m.log_bad(line), line)
        for line in ['{"level":"INFO","msg":"x","unknown":1}', '{"level":"INFO","msg":"compaction complete","level":true}', '{"level":"INFO","msg":"error applying updates"}', '{"level":"WARN","msg":"unexpected warning"}']:
            self.assertTrue(m.log_bad(line), line)

    def test_unknown_messages_and_wrong_message_fields_fail_closed(self):
        m = self.load()
        for level in ('INFO', 'DEBUG'):
            self.assertTrue(m.log_bad(json.dumps(dict(level=level, msg='unrecognized new event'))))
        self.assertTrue(m.log_bad(json.dumps(dict(level='INFO', msg='initialized db', path='/data', bucket='unexpected'))))
        self.assertTrue(m.log_bad(json.dumps(dict(level='INFO', msg='snapshot complete', txid='bad', size=1, db='main.db', system='store'))))

    def test_l0_retention_schema_is_not_a_general_log_bypass(self):
        m = self.load()
        record = dict(level='INFO', msg='l0 retention enforced', system='store', db='main.db', deleted_count=2, max_l1_txid='0000000000000005')
        self.assertFalse(m.log_bad(json.dumps(record)))
        for patch in [dict(level='ERROR'), dict(deleted_count=True), dict(max_l1_txid='5'), dict(msg='other event'), dict(error='local removal failed')]:
            self.assertTrue(m.log_bad(json.dumps(record | patch)))

    def test_database_objects_bootstrap_and_runtime_identity(self):
        m = self.load()
        self.assertTrue(hasattr(m, 'validate_databases'), 'missing database object guard')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            m.validate_databases(root, bootstrap=True)
            sidecar = root / 'main.db-wal'; sidecar.write_bytes(b'stale')
            with self.assertRaises(ValueError): m.validate_databases(root, bootstrap=True)
            sidecar.unlink()
            for name in ('main', 'session', 'aux'):
                (root / (name + '.db')).touch()
            with self.assertRaises(ValueError): m.validate_databases(root)
            for name in ('main', 'session', 'aux'):
                with sqlite3.connect(root / (name + '.db')) as db:
                    if name != 'session': db.execute('CREATE TABLE hat_ops(id INTEGER, op_key TEXT, payload TEXT)')
                    if name == 'main': db.execute('CREATE TABLE _user(id BLOB)')
                    if name == 'session': db.execute('CREATE TABLE _session(id BLOB)')
            m.validate_databases(root)
            dbpath = root / 'main.db'
            identity = m.database_identity(dbpath)
            retained = root / 'retained'; dbpath.rename(retained)
            with self.assertRaises(ValueError): m.database_identity(dbpath)
            dbpath.mkdir()
            with self.assertRaises(ValueError): m.database_identity(dbpath)
            dbpath.rmdir()
            dbpath.symlink_to(retained)
            with self.assertRaises(ValueError): m.database_identity(dbpath)
            dbpath.unlink(); dbpath.write_bytes(retained.read_bytes())
            self.assertNotEqual(m.database_identity(dbpath), identity)
            with sqlite3.connect(dbpath) as db: db.execute('DROP TABLE _user')
            with self.assertRaises(ValueError): m.validate_databases(root)

    def test_support_requires_fixed_anchors_and_confined_regular_files(self):
        m = self.load()
        self.assertTrue(hasattr(m, 'validate_support'), 'missing support identity guard')
        names = {'config.textproto', 'migrations/main/U100__hat_ops.sql', 'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem', 'secrets/keys/public_key.pem'}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest = {}
            for name in names:
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'identity')
                manifest[name] = hashlib.sha256(p.read_bytes()).hexdigest()
            m.validate_support(root, manifest)
            for bad in [None, {}, {'../escape': '0'*64}, {k:v for k,v in manifest.items() if k != 'config.textproto'}]:
                with self.assertRaises(ValueError): m.validate_support(root, bad)
            keys = root / 'secrets/keys'; retained = root / 'retained-keys'; keys.rename(retained); keys.symlink_to(retained, target_is_directory=True)
            with self.assertRaises(ValueError): m.validate_support(root, manifest)

    def test_installed_cli_has_no_promote_or_force(self):
        self.load()
        p = subprocess.run([sys.executable, str(ENTRY), '--help'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('status', p.stdout)
        self.assertNotIn('--force', p.stdout)
        p = subprocess.run([sys.executable, str(ENTRY), 'promote'], capture_output=True)
        self.assertNotEqual(p.returncode, 0)

if __name__ == '__main__': unittest.main()
