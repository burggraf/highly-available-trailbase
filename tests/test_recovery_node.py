"""Bounded D3 node action contracts; no service/provider/network calls."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

ENTRY = Path(os.environ.get('HAT_TRANSITION_ENTRY', str(Path(__file__).resolve().parents[1] / 'hat/transition.py')))


def load():
    sys.path.insert(0, str(ENTRY.parent))
    spec = importlib.util.spec_from_file_location('hat_transition_d3_node', ENTRY)
    module = importlib.util.module_from_spec(spec)
    from unittest.mock import patch
    from types import SimpleNamespace
    node_spec = importlib.util.spec_from_file_location('node', ENTRY.with_name('node.py'))
    isolated_node = importlib.util.module_from_spec(node_spec); node_spec.loader.exec_module(isolated_node)
    with patch.dict(sys.modules, {'node': isolated_node}): spec.loader.exec_module(module)
    module.os = SimpleNamespace(**vars(os)); module.pwd = SimpleNamespace(**vars(module.pwd))
    return module


class RecoveryNodeTests(unittest.TestCase):
    def test_cold_action_shapes_and_exact_bindings(self):
        m = load()
        operation = 'a' * 32
        cold = dict(epoch='d1-old', role='writer')
        inspect = dict(action='inspect-cold', operation=operation, epoch='d1-old',
                       boot_id=None, payload={})
        m.validate_request(inspect, cold, 'boot')
        prepare = dict(action='prepare-recovery', operation=operation, epoch='d1-old',
                       boot_id='boot', payload={'source_epoch': 'd1-existing-source'})
        m.validate_request(prepare, cold, 'boot')
        restore = dict(action='restore-recovery', operation=operation, epoch='d1-existing-source',
                       boot_id='boot', payload={'cut': {'main': 1, 'session': 2, 'aux': 3},
                       'fence_digest': '1' * 64})
        m.validate_request(restore, dict(epoch='d1-existing-source', role='standby'), 'boot')
        rejoin = dict(action='rejoin', operation=operation, epoch='d1-old',
                      boot_id='boot', payload={'new_epoch': 'd1-' + operation})
        m.validate_request(rejoin, dict(epoch='d1-old', role='writer'), 'boot')

    def test_prefix_rewrite_is_exactly_one_line_per_database(self):
        m = load()
        text = ''.join('  path: demos/d1-old/' + db + ' # fixed\n' for db in m.node.DBS)
        changed = m.replace_replica_prefix(text, 'd1-old', 'd1-new')
        self.assertEqual(changed.count('demos/d1-new/'), 3)
        with self.assertRaises(RuntimeError):
            m.replace_replica_prefix(text + 'path: demos/d1-old/main # duplicate\n', 'd1-old', 'd1-new')

    def test_cold_mutations_reject_current_or_mismatched_boot_and_epochs(self):
        m = load()
        operation = 'a' * 32
        signature = {db: '0' * 64 for db in ('main', 'session', 'aux')}
        request = dict(action='prepare-recovery', operation=operation, epoch='d1-old',
                       boot_id='boot', payload={'source_epoch': 'd1-existing-source'})
        for patch in ({'boot_id': 'other'}, {'epoch': 'd1-source'},
                      {'payload': request['payload'] | {'source_epoch': 'd1-old'}},
                      {'payload': request['payload'] | {'extra': 'bad'}}):
            with self.assertRaises(ValueError):
                m.validate_request(request | patch, dict(epoch='d1-old', role='writer'), 'boot')
        rejoin = dict(action='rejoin', operation=operation, epoch='d1-old', boot_id='boot',
                      payload={'new_epoch': 'd1-' + operation})
        with self.assertRaises(ValueError):
            m.validate_request(rejoin | {'payload': {'new_epoch': 'd1-old'}},
                               dict(epoch='d1-old', role='writer'), 'boot')


    def test_cold_inspection_is_read_only_and_reports_stale_authority(self):
        m = load()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            authority = Path(tmp) / 'authority'
            authority.write_text('{\"role\":\"writer\",\"epoch\":\"d1-old\",\"boot_id\":\"previous\"}')
            authority.chmod(0o600)
            replica = Path(tmp) / 'litestream.yml'; replica.write_text('native replica config\n')
            config_path = Path(tmp) / 'node.json'; config_path.write_text('{"role":"writer","epoch":"d1-old"}\n')
            old, old_replica, old_config = m.node.AUTHORITY, m.REPLICA, m.CONFIG
            m.node.AUTHORITY, m.REPLICA, m.CONFIG = authority, replica, config_path
            try:
                m._cold_safety = lambda: {'node_service': 'static', 'restart': 'no', 'legacy_services': 'masked'}
                m._authority_state = lambda c: 'stale'
                m.status = lambda: (_ for _ in ()).throw(AssertionError('cold inspection must not use HTTP'))
                m.node.boot_id = lambda: 'current'
                config = {'role': 'writer', 'epoch': 'd1-old'}
                result = m.inspect_cold({'operation': 'a' * 32}, config)
                self.assertEqual(result['authority'], 'stale')
                self.assertEqual(result['config'], config)
                self.assertEqual(result['replica_config'], 'native replica config\n')
                self.assertEqual(result['config_sha'], __import__('hashlib').sha256(config_path.read_bytes()).hexdigest())
                self.assertEqual(result['replica_sha'], __import__('hashlib').sha256(replica.read_bytes()).hexdigest())
                self.assertEqual(authority.read_text(), '{\"role\":\"writer\",\"epoch\":\"d1-old\",\"boot_id\":\"previous\"}')
            finally:
                m.node.AUTHORITY, m.REPLICA, m.CONFIG = old, old_replica, old_config

    def test_restore_recovery_binds_completed_prepare_and_fence(self):
        m = load()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); work = root / 'work'; work.mkdir()
            signature = {db: '0' * 64 for db in m.node.DBS}
            operation = 'a' * 32
            source = 'd1-existing-source'
            prepare = {'status': 'done', 'request': {'action': 'prepare-recovery', 'operation': operation, 'epoch': 'd1-old', 'boot_id': 'boot', 'payload': {'source_epoch': source}},
                       'result': {'original_epoch': 'd1-old', 'original_boot_id': 'boot', 'epoch': source, 'role': 'standby'}}
            record = work / 'prepare-recovery.json'; record.write_text(__import__('json').dumps(prepare)); record.chmod(0o600)
            m._cold_safety = lambda: None
            m._finite_restore = lambda cut, fresh, area: (fresh.mkdir(mode=0o700), signature)[1]
            request = {'operation': operation, 'epoch': source, 'boot_id': 'boot',
                       'payload': {'cut': {'main': 1, 'session': 2, 'aux': 3}, 'fence_digest': '1' * 64}}
            result = m.restore_recovery(request, {'role': 'standby', 'epoch': source}, work)
            self.assertEqual(result['signature'], signature)
            self.assertEqual(result['original_boot_id'], 'boot')
            self.assertEqual(result['fence_digest'], '1' * 64)
            bad = request | {'payload': request['payload'] | {'fence_digest': '2' * 64}}
            with self.assertRaises(RuntimeError): m.restore_recovery(bad, {'role': 'standby', 'epoch': source}, root / 'bad')

    def test_prepare_recovery_changes_only_role_epoch_and_prefixes(self):
        m = load()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            config = root / 'node.json'; config.write_text('{\"old\":true}')
            replica = root / 'litestream.yml'
            replica.write_text(''.join('path: demos/d1-old/' + db + '\n' for db in ('main', 'session', 'aux')))
            m.CONFIG, m.REPLICA = config, replica
            m._cold_safety = lambda: None
            m._authority_state = lambda c: 'absent'
            m.node.load_config = lambda path: None
            m.pwd.getpwnam = lambda name: type('Account', (), {'pw_gid': os.getgid()})()
            m.os.fchown = lambda *args: None
            m.os.chown = lambda *args: None
            c = {'role': 'writer', 'epoch': 'd1-old', 'bootstrap': True}
            operation = 'a' * 32
            request = {'operation': operation, 'epoch': 'd1-old', 'boot_id': 'boot',
                       'payload': {'source_epoch': 'd1-existing-source'}}
            work = root / 'work'; work.mkdir()
            result = m.prepare_recovery(request, c, work)
            self.assertEqual(result['epoch'], 'd1-existing-source')
            self.assertEqual(json_load(config)['role'], 'standby')
            self.assertEqual(json_load(config)['epoch'], 'd1-existing-source')
            self.assertEqual(replica.read_text().count('path: demos/d1-existing-source/'), 3)


def json_load(path):
    import json
    return json.loads(path.read_text())


if __name__ == '__main__':
    unittest.main()
