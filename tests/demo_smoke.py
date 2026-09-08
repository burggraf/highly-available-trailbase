#!/usr/bin/env python3
"""Real HTTP demo check. Credentials and token ledger must remain outside Git."""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid


def request(base, path, method='GET', body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try: r = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e: r = e
    raw = r.read()
    try: value = json.loads(raw)
    except ValueError: value = raw.decode(errors='replace')
    return r.status, value


def smoke(base, credentials, ledger, register=False):
    os.umask(0o077)
    with ledger.open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        def record(value):
            f.write(json.dumps(value) + '\n'); f.flush(); os.fsync(f.fileno())
        if register:
            code, _ = request(base, '/api/auth/v1/register', 'POST', credentials | {'password_repeat': credentials['password']})
            assert code == 200, ('register', code)
        code, first = request(base, '/api/auth/v1/login', 'POST', credentials)
        assert code == 200 and first.get('auth_token') and first.get('refresh_token'), ('login', code)
        token = first['auth_token']
        code, second = request(base, '/api/auth/v1/login', 'POST', credentials)
        assert code == 200 and second.get('refresh_token'), ('second login', code)
        code, _ = request(base, '/api/auth/v1/logout', 'POST', {'refresh_token': second['refresh_token']})
        assert code == 200, ('logout', code)
        code, _ = request(base, '/api/auth/v1/refresh', 'POST', {'refresh_token': second['refresh_token']})
        assert code in (400, 401, 403), ('revoked refresh', code)
        record({'auth_token':token, 'retained_refresh':first['refresh_token'], 'revoked_refresh':second['refresh_token']})
        for api in ('main_ops', 'aux_ops'):
            row = {'op_key': 'd1-' + uuid.uuid4().hex, 'payload': 'D1 persistent ' + api}
            record({'event':'submitted', 'api':api, 'row':row, 'time_ns':time.time_ns()})
            code, result = request(base, '/api/records/v1/' + api, 'POST', row, token)
            assert code in (200, 201) and len(result.get('ids', [])) == 1, ('create', api, code)
            record({'event':'acknowledged', 'api':api, 'row':row, 'id':result['ids'][0], 'time_ns':time.time_ns()})
            code, read = request(base, '/api/records/v1/' + api + '/' + str(result['ids'][0]), token=token)
            assert code == 200 and read['op_key'] == row['op_key'] and read['payload'] == row['payload'], ('read', api, code)
        code, _ = request(base, '/api/records/v1/main_ops')
        assert code in (401, 403), ('unauthenticated read', code)
        record({'event':'smoke_pass'})
    print('PASS: login, retained session created, revoked refresh rejected, main+aux create/read, anonymous denial')


def verify_restore(base, ledger):
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    auth = rows[0]
    code, _ = request(base, '/api/auth/v1/refresh', 'POST', {'refresh_token':auth['revoked_refresh']})
    assert code in (400, 401, 403), ('restored revocation', code)
    code, _ = request(base, '/api/auth/v1/refresh', 'POST', {'refresh_token':auth['retained_refresh']})
    assert code == 200, ('restored retained refresh', code)
    for row in rows:
        if row.get('event') != 'acknowledged': continue
        code, got = request(base, '/api/records/v1/'+row['api']+'/'+str(row['id']), token=auth['auth_token'])
        assert code == 200 and all(got[k] == v for k,v in row['row'].items()), ('restored read', code)
    print('PASS: independently restored main+aux records, shared signing identity, retained+revoked refresh')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', required=True)
    p.add_argument('--credentials', type=Path)
    p.add_argument('--ledger', type=Path, required=True)
    p.add_argument('--register', action='store_true')
    p.add_argument('--verify-restore', action='store_true')
    a = p.parse_args()
    if a.verify_restore: verify_restore(a.base, a.ledger)
    else: smoke(a.base, json.loads(a.credentials.read_text()), a.ledger, a.register)
