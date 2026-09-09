"""Real retention filesystem and full-shaped synthetic provider receipt boundaries."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.test_recovery_node import load
from tests.test_rejoin_driver import control, B_BOOT


class RejoinNativeBoundaries(unittest.TestCase):
    def test_real_inspection_and_retention_wait_through_native_initial_sample(self):
        m = load()
        operation = 'a' * 32
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            work = root / 'work'; work.mkdir(mode=0o700)
            data = root / 'depot/data'; data.mkdir(parents=True)
            (data / 'original.db').write_bytes(b'original database evidence')
            (root / 'meta').mkdir(); (root / 'meta/original').write_bytes(b'original uploader evidence')
            m.CONFIG = root / 'node.json'; m.REPLICA = root / 'replica.yml'
            m.node.BASE = root; m.node.AUTHORITY = root / 'absent-authority'
            old = dict(role='writer', epoch='d1-old-source', bootstrap=False)
            config_bytes = (json.dumps(old, indent=2) + '\n').encode()
            replica_bytes = ''.join('path: demos/d1-old-source/' + db + '\n' for db in m.node.DBS).encode()
            m.CONFIG.write_bytes(config_bytes); m.REPLICA.write_bytes(replica_bytes)
            m.node.boot_id = lambda: B_BOOT
            m.node.load_config = lambda path: json.loads(path.read_text())
            m._cold_safety = lambda: dict(node_service='static', restart='no', legacy_services='masked')
            m.pwd.getpwnam = lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            request = dict(action='rejoin', operation=operation, epoch=old['epoch'], boot_id=B_BOOT,
                           payload={'new_epoch': 'd1-' + operation})
            inspected = m.inspect_cold(request, old)
            future = request['payload']['new_epoch']
            initial = m.node.public_status(dict(role='standby', epoch=future, sampled_at=0,
                                               positions={}, refusals=['starting']), 1000)
            healthy = dict(role='standby', epoch=future, healthy=True, trailbase_running=False,
                           positions={db: 1 for db in m.node.DBS}, processes={db: True for db in m.node.DBS},
                           refusals=[])
            with patch.object(m.os, 'chown'), patch.object(m.os, 'fchown'), \
                    patch.object(m.subprocess, 'run') as service, \
                    patch.object(m, 'status', side_effect=[initial, healthy]), \
                    patch.object(m, '_standby_processes_alive') as followers, \
                    patch.object(m, '_no_writer_processes') as no_writer, \
                    patch.object(m.time, 'sleep') as wait:
                m.validate_request(request, old, B_BOOT)
                result = m.rejoin(request, old, work)
            self.assertEqual(wait.call_count, 1)
            followers.assert_called_once_with(healthy)
            no_writer.assert_called_once()
            service.assert_called_once()
            self.assertEqual(result['original_epoch'], old['epoch'])
            self.assertEqual(result['original_boot_id'], B_BOOT)
            for key, raw, retained in (
                    ('config', config_bytes, work / 'original-config.json'),
                    ('replica', replica_bytes, work / 'original-litestream.yml')):
                self.assertEqual(retained.read_bytes(), raw)
                self.assertEqual(inspected[key + '_sha'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(result['original_' + key + '_sha'], inspected[key + '_sha'])
            self.assertEqual((root / ('retained-data-' + operation) / 'original.db').read_bytes(),
                             b'original database evidence')
            self.assertEqual((root / ('retained-meta-' + operation) / 'original').read_bytes(),
                             b'original uploader evidence')
            self.assertEqual(list(data.iterdir()), [])
            self.assertEqual(json.loads(m.CONFIG.read_text())['role'], 'standby')
            self.assertEqual(m.REPLICA.read_text().count('demos/' + future + '/'), 3)

    def test_b_power_on_full_receipt_passes_real_fence_without_guest_boot(self):
        # Synthetic values with the native adapter's complete receipt structure.
        now = 1788920000.0
        stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()
        target = dict(node='fm2', instance_id=2, provider_label='fixture-b',
                      address='192.0.2.2', host_key='fixture-host-key')
        receipt = dict(action='power-on', target=target, request={'id': 'fixture-request', 'time': stamp},
                       completion={'time': stamp}, state='running', observations=[
                           {'time': stamp, 'state': 'offline'},
                           {'time': stamp, 'state': 'running', 'identity': {
                               'instance_id': 2, 'provider_label': 'fixture-b', 'addresses': ['192.0.2.2']}}])
        io = control.ControlIO(Mock(), {'nodes': {'B': {'address': target['address']}}},
                               {'id': 'a' * 32}, Path('/unused'), {})
        with patch.object(io, '_fence_target', return_value=(Path('/unused-target'), target)), \
                patch.object(io, 'command', return_value=json.dumps(receipt).encode()) as command, \
                patch.object(control.time, 'time', return_value=now), \
                patch.object(control.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('192.0.2.2', 0))]):
            self.assertEqual(io.fence('power-on', 'running', label='B'), receipt)
            command.assert_called_once()
            receipt['observations'][-1]['identity']['instance_id'] = 3
            command.return_value = json.dumps(receipt).encode()
            with self.assertRaises(ValueError): io.fence('power-on', 'running', label='B')


if __name__ == '__main__':
    unittest.main()
