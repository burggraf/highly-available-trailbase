"""Consumers must accept native captured statuses/argv, not invented readiness shapes."""
import copy
import json
from pathlib import Path
import unittest
from tests.test_recovery_node import load

FIXTURES=Path(__file__).parent/'fixtures'

class NativeStandbyContract(unittest.TestCase):
    def test_actual_restoring_and_ready_statuses(self):
        m=load();states=json.loads((FIXTURES/'d3-native-standby-status.json').read_text())
        for state in states:
            self.assertEqual(m._standby_health(state,state['epoch'],{db:1 for db in m.node.DBS}),state)
        ready=states[-1]
        for patch in ({'refusals':['required database positions unconfirmed']},{'phase':'starting'},{'healthy':'true'},{'trailbase_running':None}):
            with self.assertRaises(RuntimeError):m._standby_health(ready|patch,ready['epoch'],{db:1 for db in m.node.DBS})
        with self.assertRaises(RuntimeError):m._standby_health(states[0]|{'refusals':['main: error or unknown log; inspect protected log']},ready['epoch'],{db:1 for db in m.node.DBS})

    def test_restoring_status_requires_captured_process_map(self):
        m=load(); states=json.loads((FIXTURES/'d3-native-standby-status.json').read_text())
        with self.assertRaises(RuntimeError):
            m._standby_health({key: value for key, value in states[0].items() if key != 'processes'},
                              states[0]['epoch'], {db: 1 for db in m.node.DBS})

    def test_initial_state_uses_actual_public_status_producer(self):
        m=load();initial=m.node.public_status(dict(role='standby',epoch='d1-source',sampled_at=0,positions={},refusals=['starting']),1000)
        self.assertFalse(m._standby_health(initial,'d1-source',{db:1 for db in m.node.DBS})['healthy'])
        with self.assertRaises(RuntimeError):m._standby_health(initial|{'sampled_at':1},'d1-source',{db:1 for db in m.node.DBS})

    def test_prepare_refuses_unsafe_recovery_record_before_copying(self):
        import tempfile,os
        m=load();m.empty_cgroup=lambda:None
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();m.node.AUTHORITY=root/'no-authority'
            record=root/'restore-recovery.json';record.write_text(json.dumps({'status':'done'}));record.chmod(0o644)
            request={'action':'prepare','payload':{}}
            with self.assertRaises(ValueError):m.execute(request,{'role':'standby'},root)
            record.chmod(0o600);os.link(record,root/'extra-link')
            with self.assertRaises(ValueError):m.execute(request,{'role':'standby'},root)

    def test_exact_native_follower_bindings_and_unique_database_set(self):
        m=load();original=json.loads((FIXTURES/'d3-native-follower-argv.json').read_text())
        value={'processes':{db:True for db in m.node.DBS}}
        args=copy.deepcopy(original)
        m._pgrep=lambda name:list(range(3)) if name=='litestream' else []
        m._process_commandline=lambda pid:args[pid]
        m._standby_processes_alive(value);m._no_writer_processes()
        for index,bad in ((0,'/tmp/litestream'),(3,'/tmp/other.yml'),(8,'/tmp/main.db'),(9,'/tmp/main.db')):
            args=copy.deepcopy(original);args[0][index]=bad
            with self.assertRaises(RuntimeError):m._standby_processes_alive(value)
            with self.assertRaises(RuntimeError):m._no_writer_processes()
        args=[original[0],original[0],original[2]]
        with self.assertRaises(RuntimeError):m._standby_processes_alive(value)

if __name__=='__main__':unittest.main()
