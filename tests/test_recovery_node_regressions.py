"""Parent regressions for source/target epoch separation and real authority modes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tests.test_recovery_node import load


class NodeRegressions(unittest.TestCase):
    def test_existing_source_epoch_is_not_reserved_target_epoch(self):
        m=load();operation='a'*32;source='d1-'+'b'*32
        old=dict(role='writer',epoch='d1-historical')
        setup=dict(action='prepare-recovery',operation=operation,epoch=old['epoch'],boot_id='boot',payload={'source_epoch':source})
        m.validate_request(setup,old,'boot')
        future=dict(role='standby',epoch=source)
        promote=dict(action='prepare',operation=operation,epoch=source,boot_id='boot',payload=dict(new_epoch='d1-'+operation,signature={db:'c'*64 for db in m.node.DBS},fence_digest='d'*64))
        m.validate_request(promote,future,'boot')
        with self.assertRaises(ValueError):m.validate_request(setup|{'payload':{'source_epoch':'d1-'+operation}},old,'boot')
        with self.assertRaises(ValueError):m.validate_request(promote|{'payload':promote['payload']|{'new_epoch':'d1-unreserved'}},future,'boot')

    def test_cold_setup_restore_and_promotion_sequence_with_real_files(self):
        import sqlite3
        from types import SimpleNamespace
        m=load();operation='a'*32;source='d1-'+'b'*32;cut={db:2 for db in m.node.DBS}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();work=root/'work';work.mkdir(mode=0o700)
            data=root/'depot/data';data.mkdir(parents=True);(data/'old-evidence').write_text('retain')
            (root/'meta').mkdir();(root/'meta/old-meta').write_text('retain')
            m.CONFIG=root/'node.json';m.REPLICA=root/'replica.yml';m.node.BASE=root;m.node.AUTHORITY=root/'absent-authority'
            old=dict(role='writer',epoch='d1-history',bootstrap=False)
            m.CONFIG.write_text(json.dumps(old));m.REPLICA.write_text(''.join('path: demos/d1-history/'+db+'\n' for db in m.node.DBS))
            m._cold_safety=lambda:None;m.empty_cgroup=lambda:None
            m.node.load_config=lambda path:json.loads(path.read_text())
            account=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            m.pwd.getpwnam=lambda _:account
            m._backup_credentials=lambda:{}
            def fake_binary(args,area,**kwargs):
                self.assertEqual(args[1],'restore');self.assertIn('-txid',args)
                target=Path(args[args.index('-o')+1]);name=target.stem
                with sqlite3.connect(target) as db:
                    if name!='session':db.execute('CREATE TABLE hat_ops(id INTEGER,op_key TEXT,payload TEXT)')
                    db.execute('CREATE TABLE '+('_session' if name=='session' else '_user')+'(id BLOB)')
                target.chmod(0o600)
            m.run=fake_binary
            def step(action,config,payload):
                request=dict(action=action,operation=operation,epoch=config['epoch'],boot_id='boot',payload=payload)
                m.validate_request(request,config,'boot')
                record=work/(action+'.json');m.atomic_json(record,dict(status='intent',request=request))
                result=m.execute(request,config,work);m.atomic_json(record,dict(status='done',request=request,result=result))
                return result
            with patch.object(m.os,'chown') as chown,patch.object(m.os,'fchown'):
                step('prepare-recovery',old,dict(source_epoch=source))
                self.assertEqual((data/'old-evidence').read_text(),'retain')
                standby=json.loads(m.CONFIG.read_text());self.assertEqual(standby['epoch'],source)
                restored=step('restore-recovery',standby,dict(cut=cut,fence_digest='d'*64))
                step('prepare',standby,dict(new_epoch='d1-'+operation,signature=restored['signature'],fence_digest='d'*64))
                chown.assert_any_call(m.CONFIG,0,account.pw_gid)
                chown.assert_any_call(data,account.pw_uid,account.pw_gid)
            self.assertEqual(json.loads(m.CONFIG.read_text())['epoch'],'d1-'+operation)
            self.assertEqual((root/('retained-data-'+operation)/'old-evidence').read_text(),'retain')
            self.assertEqual((root/('retained-meta-'+operation)/'old-meta').read_text(),'retain')
            self.assertEqual(m.logical_signature(data),restored['signature'])
            self.assertFalse(m.node.AUTHORITY.exists())

    def test_rejoin_readiness_accepts_bounded_restore_progress_then_ready(self):
        m = load(); epoch = 'd1-new'; cut = {db: 1 for db in m.node.DBS}
        starting = m.node.public_status(dict(role='standby', epoch=epoch, sampled_at=0,
                                             refusals=['starting'], positions={}), 1000)
        captured = json.loads((Path(__file__).parent/'fixtures/d3-native-standby-status.json').read_text())
        restoring, ready = [state | {'epoch':epoch} for state in captured]
        self.assertIs(m._standby_health(starting, epoch, cut)['healthy'], False)
        self.assertIs(m._standby_health(restoring, epoch, cut)['healthy'], False)
        self.assertIs(m._standby_health(ready, epoch, cut)['healthy'], True)
        for bad in (dict(starting, role='writer'), dict(starting, epoch='d1-other'),
                    dict(starting, refusals=['sticky log refusal']),
                    dict(restoring, processes=dict(restoring['processes'], main=False))):
            with self.assertRaises(RuntimeError): m._standby_health(bad, epoch, cut)

    def test_rejoin_readiness_rejects_unknown_or_unreadable_follower_argv(self):
        m = load(); value = dict(role='standby', epoch='d1-new', refusals=[], positions={db: 1 for db in m.node.DBS},
                                 healthy=True, processes={db: True for db in m.node.DBS})
        with patch.object(m, '_pgrep', return_value=[11, 12, 13]), patch.object(
                m, '_process_commandline', side_effect=[["litestream", "restore", "-config", "x", "-f", "-follow-interval", "1s", "-o", "a"], OSError(), []]):
            with self.assertRaises((RuntimeError, OSError)):
                m._standby_processes_alive(value)
        with patch.object(m, '_pgrep', return_value=[11]), self.assertRaises(RuntimeError):
            m._standby_processes_alive(value)

    def test_real_0644_authority_and_malformed_old_boot_fields(self):
        m=load()
        with tempfile.TemporaryDirectory() as tmp:
            authority=Path(tmp).resolve()/'authority.json';authority.write_text(json.dumps(dict(role='writer',epoch='d1-old',boot_id='old-boot')));authority.chmod(0o644)
            original=Path.lstat
            def root_owner(path,*args,**kwargs):
                value=original(path,*args,**kwargs)
                # Only UID is simulated on macOS; mode/type/link count are real filesystem values.
                return os.stat_result(tuple(value[:4])+(0,)+tuple(value[5:])) if path==authority else value
            with patch.object(m.node,'AUTHORITY',authority),patch.object(m.node,'boot_id',return_value='new-boot'),patch.object(Path,'lstat',root_owner):
                self.assertEqual(m._authority_state(dict(role='writer',epoch='d1-old')),'stale')
                authority.chmod(0o666)
                self.assertEqual(m._authority_state(dict(role='writer',epoch='d1-old')),'unsafe')
                authority.chmod(0o644)
                for bad in (dict(role='writer',epoch=None,boot_id=None),dict(role='writer',epoch='d1-old',boot_id='new-boot'),[]):
                    authority.write_text(json.dumps(bad))
                    with self.assertRaises(RuntimeError):m._authority_state(dict(role='writer',epoch='d1-other'))

if __name__=='__main__':unittest.main()
