import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hat'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import recovery
import control

class RestoreTask3Tests(unittest.TestCase):
    def test_installed_manifest_can_hold_fixed_tree_authority(self):
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        support = root / 'support'; support.mkdir(mode=0o700)
        item = support / 'fixed'; item.write_bytes(b'fixed'); item.chmod(0o600)
        io = control.ControlIO.__new__(control.ControlIO)
        manifest, held = io._installed_manifest(
            root, ('support/fixed',), os.geteuid(), os.getegid(), 0o600, hold=True)
        try:
            self.assertEqual(manifest, {'support/fixed': hashlib.sha256(b'fixed').hexdigest()})
            item.rename(support / 'old')
            item.write_bytes(b'fixed'); item.chmod(0o600)
            with self.assertRaises(ValueError):
                for authority in held:
                    authority.recheck()
        finally:
            for authority in reversed(held):
                authority.close()

    def test_oracle_raw_rejects_symlinked_ancestor(self):
        import restore_baseline
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        real = root / 'real'; real.mkdir(); (real / 'x').write_bytes(b'x')
        link = root / 'link'; link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError): restore_baseline._raw(link / 'x')

    def test_oracle_fixed_support_rejects_extra_file(self):
        import restore_baseline
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        source = root / 'support'; source.mkdir()
        (source / 'ok').write_bytes(b'ok'); (source / 'extra').write_bytes(b'x')
        with self.assertRaises(ValueError): restore_baseline._validate_fixed_files(source, {'ok': '0' * 64}, os.geteuid(), os.getegid(), 0o600)

    def test_fixed_installed_files_refuse_mode_gid_link_extra_directory_and_replacement(self):
        import restore_baseline
        for mutation in ('mode', 'gid', 'link', 'extra-directory'):
            with self.subTest(mutation=mutation):
                root = Path(tempfile.mkdtemp(dir=Path.cwd())); (root / 'nested').mkdir(mode=0o700)
                item = root / 'nested/ok'; item.write_bytes(b'ok'); item.chmod(0o600)
                expected_gid = os.getegid()
                if mutation == 'mode': item.chmod(0o640)
                elif mutation == 'gid': expected_gid += 1
                elif mutation == 'link': os.link(item, root / 'linked')
                elif mutation == 'extra-directory': (root / 'extra').mkdir()
                with self.assertRaises(ValueError):
                    restore_baseline._validate_fixed_files(
                        root, {'nested/ok': hashlib.sha256(b'ok').hexdigest()},
                        os.geteuid(), expected_gid, 0o600)
        root = Path(tempfile.mkdtemp(dir=Path.cwd())); item = root / 'ok'
        item.write_bytes(b'ok'); item.chmod(0o600)
        held = restore_baseline._validate_fixed_files(
            root, {'ok': hashlib.sha256(b'ok').hexdigest()}, os.geteuid(), os.getegid(), 0o600)
        item.rename(root / 'old'); item.write_bytes(b'ok'); item.chmod(0o600)
        try:
            with self.assertRaises(ValueError): held[-1].recheck()
        finally:
            for authority in reversed(held): authority.close()

    def test_canonical_wire_authority_reaches_beyond_ledger_comparison_without_gid(self):
        import restore_baseline
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        ledger = root / 'ledger.jsonl'; ledger.write_bytes(b'ledger\n'); ledger.chmod(0o600)
        config = root / 'replica.yml'; config.write_bytes(b'config')
        request_path = root / 'acceptance-request.json'; request_path.write_bytes(b'{}')
        info = ledger.stat()
        wire = {'path': str(ledger.resolve()), 'device': info.st_dev, 'inode': info.st_ino,
                'mode': info.st_mode & 0o777, 'uid': info.st_uid, 'links': info.st_nlink,
                'bytes': info.st_size, 'sha256': hashlib.sha256(ledger.read_bytes()).hexdigest()}
        request = {'operation': 'a' * 32, 'source': 'A', 'target': 'B', 'epoch': 'd1-source',
                   'phase': 'compare', 'profile': 'comparison',
                   'inputs': {'replica_config_sha256': hashlib.sha256(b'config').hexdigest(),
                              'ledger_sha256': wire['sha256'],
                              'ledger_authority': {'ledger': wire}}}
        with unittest.mock.patch.object(restore_baseline.recovery, 'parse_canonical_json', return_value=request), \
             unittest.mock.patch.object(restore_baseline.recovery, 'parse_acceptance_request', return_value=request), \
             unittest.mock.patch.object(restore_baseline.recovery, '_replica_config'), \
             unittest.mock.patch.object(restore_baseline.recovery, '_protected_ledger', side_effect=RuntimeError('past-authority')):
            with self.assertRaisesRegex(RuntimeError, 'past-authority'):
                restore_baseline.restore(root, request_path, config, ledger, root, root)

    def test_internal_descriptor_identity_still_rejects_gid_mutation(self):
        import restore_baseline
        root = Path(tempfile.mkdtemp(dir=Path.cwd()))
        item = root / 'ledger.jsonl'; item.write_bytes(b'ledger\n'); item.chmod(0o600)
        expected = list(restore_baseline._stat_identity(item.stat()))
        expected[4] += 1
        with self.assertRaises(ValueError):
            restore_baseline._raw(item, expected=tuple(expected))

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
