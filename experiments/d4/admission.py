"""Local write-admission protocol experiment; deliberately not a deployable proxy."""
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

MAX_BODY = 1024 * 1024
SURFACES = {
    ('POST', '/api/records/v1/main_ops'): 'main',
    ('POST', '/api/records/v1/aux_ops'): 'aux',
    ('POST', '/api/auth/v1/login'): 'session',
    ('POST', '/api/auth/v1/logout'): 'session',
    ('POST', '/api/auth/v1/refresh'): 'session',
}
_OPERATION = re.compile(r'[0-9a-f]{32}')
_EPOCH = re.compile(r'd1-[a-z0-9-]{1,124}')
_BOOT = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_EVIDENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_REQUEST_KEYS = {'operation_id', 'method', 'path', 'body', 'headers', 'epoch', 'writer_boot'}
_HEADER_KEYS = {'content-type', 'authorization', 'cookie'}


@dataclass(frozen=True)
class Decision:
    released: bool
    status: int
    body: bytes
    reason: str


def _private_file(path):
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
            or value.st_mode & 0o077 or value.st_nlink != 1):
        raise ValueError('admission journal file must be private')
    return value.st_dev, value.st_ino


class AdmissionJournal:
    """Single local owner and permanently single-use operation identities."""
    def __init__(self, root):
        self.root = Path(root)
        self.lock = None
        self.db = None

    def __enter__(self):
        try:
            value = self.root.lstat()
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
                    or value.st_mode & 0o077 or any(path.is_symlink() for path in self.root.parents)):
                raise ValueError('admission journal directory must be private')
            self.root_identity = value.st_dev, value.st_ino
            self.lock = os.open(self.root / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            _private_file(self.root / 'lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root / 'journal.db'
            for suffix in ('', '-journal', '-wal', '-shm'):
                candidate = self.root / ('journal.db' + suffix)
                if candidate.exists() or candidate.is_symlink():
                    _private_file(candidate)
            existing = path.exists()
            if existing:
                if not path.stat().st_size:
                    raise ValueError('empty admission journal')
            else:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            self.db = sqlite3.connect(path, timeout=0)
            if existing:
                tables = {row[0] for row in self.db.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'")}
                if tables != {'operations'} or self.db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise ValueError('unrecognized admission journal')
                columns = [row[1] for row in self.db.execute('PRAGMA table_info(operations)')]
                if columns != ['operation', 'request_digest', 'method', 'path', 'epoch', 'writer_boot',
                               'database_name', 'status', 'upstream_status', 'upstream_digest',
                               'proof_evidence', 'txid']:
                    raise ValueError('unrecognized admission journal schema')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=EXTRA')
            self.db.execute('''CREATE TABLE IF NOT EXISTS operations (
                operation TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                epoch TEXT NOT NULL,
                writer_boot TEXT NOT NULL,
                database_name TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN
                    ('intent','forward_uncertain','awaiting_proof','proof_uncertain','proven')),
                upstream_status INTEGER,
                upstream_digest TEXT,
                proof_evidence TEXT,
                txid INTEGER)''')
            self.database_identity = _private_file(path)
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def check_authority(self):
        if self.lock is None or self.db is None:
            raise RuntimeError('admission journal is not locked')
        root = self.root.lstat()
        locked = os.fstat(self.lock)
        if ((root.st_dev, root.st_ino) != self.root_identity
                or _private_file(self.root / 'lock') != (locked.st_dev, locked.st_ino)
                or _private_file(self.root / 'journal.db') != self.database_identity):
            raise RuntimeError('journal authority lost')

    def begin(self, request, digest, database):
        self.check_authority()
        if self.db.execute('SELECT 1 FROM operations WHERE operation=?',
                           (request['operation_id'],)).fetchone():
            raise RuntimeError('operation identity already used')
        with self.db:
            self.db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (request['operation_id'], digest, request['method'], request['path'], request['epoch'],
                 request['writer_boot'], database, 'intent', None, None, None, None))
        return request['operation_id']

    def update(self, operation, old_status, status, upstream_status=None,
               upstream_digest=None, proof_evidence=None, txid=None):
        self.check_authority()
        with self.db:
            cursor = self.db.execute('''UPDATE operations SET status=?,upstream_status=?,upstream_digest=?,
                proof_evidence=?,txid=? WHERE operation=? AND status=?''',
                (status, upstream_status, upstream_digest, proof_evidence, txid, operation, old_status))
            if cursor.rowcount != 1:
                raise RuntimeError('admission journal state differs')


def _request(value):
    try:
        valid = (isinstance(value, dict) and set(value) == _REQUEST_KEYS
                 and isinstance(value['operation_id'], str) and _OPERATION.fullmatch(value['operation_id'])
                 and (value['method'], value['path']) in SURFACES
                 and isinstance(value['body'], bytes) and len(value['body']) <= MAX_BODY
                 and isinstance(value['headers'], dict) and set(value['headers']) <= _HEADER_KEYS
                 and all(isinstance(key, str) and isinstance(item, str) and len(item) <= 8192
                         for key, item in value['headers'].items())
                 and isinstance(value['epoch'], str) and _EPOCH.fullmatch(value['epoch'])
                 and isinstance(value['writer_boot'], str) and _BOOT.fullmatch(value['writer_boot']))
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise ValueError('invalid admission request')
    digest = hashlib.sha256()
    for item in (value['method'].encode(), value['path'].encode(), value['epoch'].encode(),
                 value['writer_boot'].encode(), value['body']):
        digest.update(len(item).to_bytes(8, 'big'))
        digest.update(item)
    for key, item in sorted(value['headers'].items()):
        encoded = (key + ':' + item).encode()
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
    return digest.hexdigest(), SURFACES[(value['method'], value['path'])]


def _outcome(value):
    valid = (isinstance(value, dict) and set(value) == {'status', 'response_body', 'mutation'}
             and type(value['status']) is int and 100 <= value['status'] <= 599
             and isinstance(value['response_body'], bytes) and len(value['response_body']) <= MAX_BODY
             and value['mutation'] in ('possible', 'completed')
             and (value['mutation'] != 'completed' or 200 <= value['status'] <= 299))
    if not valid:
        raise ValueError('invalid upstream outcome')
    return value


def _proof(value, requirement):
    keys = {'operation_id', 'request_digest', 'epoch', 'writer_boot', 'database',
            'txid', 'replica_txid', 'image_verified', 'evidence_id'}
    valid = (isinstance(value, dict) and set(value) == keys
             and all(value.get(key) == requirement[key]
                     for key in ('operation_id', 'request_digest', 'epoch', 'writer_boot', 'database'))
             and type(value.get('txid')) is int and value['txid'] > 0
             and type(value.get('replica_txid')) is int and value['replica_txid'] == value['txid']
             and value.get('image_verified') is True
             and isinstance(value.get('evidence_id'), str) and _EVIDENCE.fullmatch(value['evidence_id']))
    if not valid:
        raise ValueError('invalid admission proof')
    return value


def admit(journal, request, forward, prove):
    """Forward once and release success only after a bound supplied proof validates."""
    digest, database = _request(request)
    operation = journal.begin(request, digest, database)
    binding = {'operation_id': operation, 'request_digest': digest, 'epoch': request['epoch'],
               'writer_boot': request['writer_boot'], 'database': database}
    forwarded_request = dict(request, headers=dict(request['headers']))
    try:
        outcome = _outcome(forward(forwarded_request))
    except Exception:
        journal.update(operation, 'intent', 'forward_uncertain')
        return Decision(False, 503, b'admission forward uncertain', 'forward_uncertain')
    upstream_digest = hashlib.sha256(outcome['response_body']).hexdigest()
    journal.update(operation, 'intent', 'awaiting_proof', outcome['status'], upstream_digest)
    try:
        proof = _proof(prove(dict(binding)), binding)
    except Exception:
        journal.update(operation, 'awaiting_proof', 'proof_uncertain',
                       outcome['status'], upstream_digest)
        return Decision(False, 503, b'admission proof uncertain', 'proof_uncertain')
    journal.update(operation, 'awaiting_proof', 'proven', outcome['status'], upstream_digest,
                   proof['evidence_id'], proof['txid'])
    return Decision(True, outcome['status'], outcome['response_body'], 'proven')
