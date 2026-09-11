"""Minimal canonical restore acceptance values for controller tests."""
import hashlib
import json

DBS = ('main', 'session', 'aux')
SUPPORT = ('config.textproto', 'migrations/main/U100__hat_ops.sql',
           'migrations/aux/U100__hat_ops.sql', 'secrets/keys/private_key.pem',
           'secrets/keys/public_key.pem')


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def acceptance_result(operation, phase, positions, signature=None, checks=None):
    recovery_compare = phase == 'compare' and operation['source'] == 'B'
    profile = 'recovery-comparison' if recovery_compare else {
        'compare': 'comparison', 'reconciled-compare': 'comparison',
        'baseline': 'baseline', 'verification-baseline': 'baseline',
        'new-writes': 'fresh-writes',
    }[phase]
    epoch = operation['source_epoch'] if phase in ('compare', 'reconciled-compare') else operation['new_epoch']
    origin = ('current-verify-exclusive' if phase == 'new-writes' else
              'd3-recovery-input' if operation['source'] == 'B' else 'd2-preflight')
    support = {name: 'b' * 64 for name in SUPPORT}
    authority = {
        'schema': 'hat-restore-input-authority-1', 'operation': operation['id'],
        'origin': origin,
        'ledger': {
            'path': f"/var/lib/hat-control/{operation['id']}/" +
                    ('new-writes.jsonl' if phase == 'new-writes' else 'ledger.jsonl'),
            'device': 1, 'inode': 2, 'mode': 0o600, 'uid': 0,
            'links': 1, 'bytes': 10, 'sha256': 'a' * 64,
        },
        'support': support, 'binaries': {'trail': 'c' * 64, 'litestream': 'd' * 64},
    }
    inputs = {
        'replica_config_sha256': 'e' * 64, 'ledger_sha256': 'a' * 64,
        'ledger_authority': authority,
        'restore_points': {db: {'source': f'/var/lib/hat-demo/depot/data/{db}.db',
                                'position': positions[db]} for db in DBS},
        'support': support, 'binaries': authority['binaries'],
    }
    if recovery_compare:
        operations = ['main_ops/d3-fault']
        inputs.update(fault_ledger_sha256='f' * 64, fault_operations=operations,
                      fault_operation_count=len(operations),
                      fault_operations_sha256=hashlib.sha256(canonical_json(operations)).hexdigest())
    request = {
        'schema': 'hat-restore-acceptance-1', 'operation': operation['id'],
        'phase': phase, 'source': operation['source'], 'target': operation['target'],
        'epoch': epoch, 'positions': dict(positions), 'profile': profile, 'inputs': inputs,
    }
    if checks is None:
        checks = {'records': 'PASS', 'authentication': 'PASS'}
        if recovery_compare:
            checks |= {'fault_outcomes': {'recovered': operations, 'lost': [], 'ambiguous': [],
                                          'unacknowledged_recovered': [], 'rejected': []},
                       'acknowledged_loss': 'NONE'}
    return {
        'schema': 'hat-restore-acceptance-1', 'request': request,
        'request_sha256': hashlib.sha256(canonical_json(request)).hexdigest(),
        'databases': {db: {'position': positions[db], 'sha256': '9' * 64,
                           'integrity': 'PASS', 'foreign_keys': 'PASS'} for db in DBS},
        'signature': signature or {db: hashlib.sha256((phase + db).encode()).hexdigest()
                                   for db in DBS},
        'checks': checks,
    }
