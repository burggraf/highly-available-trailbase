"""Fresh local native proof adapter experiment; no listener or deployment wiring."""
from contextlib import closing
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import sqlite3
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import admission

MAX_BODY = 1024 * 1024
MAX_COMMAND_OUTPUT = 1024 * 1024
FIRST_SLICE = {
    ('POST', '/api/records/v1/main_ops'): 'main',
    ('POST', '/api/records/v1/aux_ops'): 'aux',
}
_DIGEST = re.compile(r'[0-9a-f]{64}')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def _private_regular(path):
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
            or value.st_mode & 0o077 or value.st_nlink != 1):
        raise ValueError('native adapter file must be private')


class CommandOutputLimit(RuntimeError):
    def __init__(self, stdout, stderr):
        super().__init__('native adapter command output exceeded limit')
        self.stdout, self.stderr = stdout, stderr


class CommandCleanupUncertain(RuntimeError):
    def __init__(self, stdout, stderr):
        super().__init__('native adapter command cleanup uncertain')
        self.stdout = bytes(stdout or b'')[:MAX_COMMAND_OUTPUT]
        self.stderr = bytes(stderr or b'')[:MAX_COMMAND_OUTPUT]


def _stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=2)
    deadline = time.monotonic() + 2
    cleanup_uncertain = False
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return stdout, stderr
        except PermissionError as error:
            if error.errno != errno.EPERM:
                raise
            cleanup_uncertain = True
        if time.monotonic() >= deadline:
            if cleanup_uncertain:
                raise CommandCleanupUncertain(stdout, stderr)
            raise RuntimeError('native adapter process group survived termination')
        time.sleep(0.01)


def _run_group(argv, environment, timeout):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, start_new_session=True)
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                tail_stdout, tail_stderr = _stop_group(process)
                stdout = (bytes(output[process.stdout]) + (tail_stdout or b''))[:MAX_COMMAND_OUTPUT]
                stderr = (bytes(output[process.stderr]) + (tail_stderr or b''))[:MAX_COMMAND_OUTPUT]
                raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr)
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                value = output[key.fileobj]
                if len(value) + len(chunk) > MAX_COMMAND_OUTPUT:
                    value.extend(chunk[:MAX_COMMAND_OUTPUT - len(value)])
                    _stop_group(process)
                    raise CommandOutputLimit(bytes(output[process.stdout]),
                                             bytes(output[process.stderr]))
                value.extend(chunk)
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _stop_group(process)
            raise subprocess.TimeoutExpired(argv, timeout, output=bytes(output[process.stdout]),
                                            stderr=bytes(output[process.stderr])) from None
        return subprocess.CompletedProcess(argv, process.returncode,
                                           bytes(output[process.stdout]), bytes(output[process.stderr]))
    finally:
        selector.close()


def _write(path, data):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class NativeAdapter:
    """One-process local fixture adapter for exact collection-create operations."""
    DATABASES = {'main', 'aux'}

    def __init__(self, *, root, base_url, litestream, binary_sha256, socket_path,
                 config, databases, opener=None, runner=None):
        raw_root = Path(root)
        if '..' in raw_root.parts:
            raise ValueError('native adapter root parent traversal is forbidden')
        original_root = raw_root if raw_root.is_absolute() else Path.cwd() / raw_root
        current = Path(original_root.anchor)
        for part in original_root.parts[1:]:
            current = current / part
            if current.is_symlink():
                raise ValueError('native adapter root components must not be symlinked')
        self.root = original_root.resolve()
        value = self.root.lstat()
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
                or value.st_mode & 0o077 or any(path.is_symlink() for path in self.root.parents)):
            raise ValueError('native adapter root must be private')
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username
                or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or parsed.port is None):
            raise ValueError('native adapter requires an exact loopback URL')
        self.root_identity = value.st_dev, value.st_ino
        self.identities = {}
        self.base_url = f'http://127.0.0.1:{parsed.port}'
        self.litestream = self._path(litestream, regular=True)
        self.config = self._path(config, regular=True)
        self.socket_path = self._path(socket_path)
        sock = self.socket_path.lstat()
        if (not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != os.geteuid() or sock.st_mode & 0o077):
            raise ValueError('native adapter socket must be private')
        self.identities[self.socket_path] = (sock.st_dev, sock.st_ino, 'socket')
        if not isinstance(binary_sha256, str) or not _DIGEST.fullmatch(binary_sha256):
            raise ValueError('invalid native adapter binary digest')
        if hashlib.sha256(self.litestream.read_bytes()).hexdigest() != binary_sha256:
            raise ValueError('native adapter binary differs')
        self.binary_sha256 = binary_sha256
        if not isinstance(databases, dict) or set(databases) != self.DATABASES:
            raise ValueError('native adapter databases differ')
        self.databases = {name: self._path(path, regular=True) for name, path in databases.items()}
        self.evidence = self.root / 'evidence'
        if self.evidence.exists() or self.evidence.is_symlink():
            evidence = self.evidence.lstat()
            if (not stat.S_ISDIR(evidence.st_mode) or evidence.st_uid != os.geteuid()
                    or evidence.st_mode & 0o077 or self.evidence.is_symlink()):
                raise ValueError('native adapter evidence directory must be private')
        else:
            self.evidence.mkdir(mode=0o700)
        evidence = self.evidence.lstat()
        self.identities[self.evidence] = (evidence.st_dev, evidence.st_ino, 'directory')
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        self.runner = runner
        self.contexts = {}

    def _path(self, value, regular=False):
        original = Path(value).absolute()
        try:
            relative = original.relative_to(self.root)
        except ValueError:
            raise ValueError('native adapter path escapes root') from None
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('native adapter path components must not be symlinked')
        if regular:
            _private_regular(original)
        path = original.resolve()
        if path == self.root or self.root not in path.parents:
            raise ValueError('native adapter path escapes root')
        if regular:
            value = path.lstat()
            self.identities[path] = (value.st_dev, value.st_ino, 'regular')
        return path

    def _revalidate(self, path):
        root = self.root.lstat()
        if (root.st_dev, root.st_ino) != self.root_identity:
            raise RuntimeError('native adapter root identity changed')
        relative = path.relative_to(self.root)
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise RuntimeError('native adapter path became symlinked')
        value = path.lstat()
        expected = self.identities[path]
        kind = ('regular' if stat.S_ISREG(value.st_mode) else
                'socket' if stat.S_ISSOCK(value.st_mode) else
                'directory' if stat.S_ISDIR(value.st_mode) else 'other')
        if ((value.st_dev, value.st_ino, kind) != expected or value.st_uid != os.geteuid()
                or value.st_mode & 0o077 or kind == 'regular' and value.st_nlink != 1):
            raise RuntimeError('native adapter path identity changed')

    def validate_policy(self, request):
        try:
            if (not isinstance(request, dict)
                    or (request.get('method'), request.get('path')) not in FIRST_SLICE
                    or not isinstance(request.get('body'), bytes)):
                raise ValueError
            body = _json(request['body'])
            if (not isinstance(body, dict) or set(body) != {'op_key', 'payload'}
                    or any(not isinstance(body[key], str) or not 1 <= len(body[key]) <= 1024
                           for key in ('op_key', 'payload'))):
                raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            raise ValueError('unsupported native adapter request') from None
        return FIRST_SLICE[(request['method'], request['path'])], body

    def forward(self, request):
        database, body = self.validate_policy(request)
        operation = request['operation_id']
        if operation in self.contexts:
            raise RuntimeError('native adapter operation already forwarded')
        web_request = urllib.request.Request(self.base_url + request['path'], request['body'],
                                             request['headers'], method=request['method'])
        try:
            response = self.opener.open(web_request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
        if len(raw) > MAX_BODY or type(status) is not int or not 100 <= status <= 599:
            raise ValueError('invalid native upstream response')
        digest, bound_database = admission._request(request)
        if bound_database != database:
            raise RuntimeError('native adapter request binding differs')
        self.contexts[operation] = {'database': database, 'request_body': body,
                                    'status': status, 'response_body': raw,
                                    'binding': {'operation_id': operation, 'request_digest': digest,
                                                'epoch': request['epoch'], 'writer_boot': request['writer_boot'],
                                                'database': database}}
        return {'status': status, 'response_body': raw,
                'mutation': 'completed' if 200 <= status <= 299 else 'possible'}

    def _command(self, directory, label, argv):
        self._revalidate(directory)
        _write(directory / (label + '.intent.json'),
               json.dumps({'argv': [str(value) for value in argv]}, separators=(',', ':')).encode())
        environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                       'HOME': str(self.root), 'TMPDIR': str(self.root)}
        try:
            if self.runner is None:
                result = _run_group([str(value) for value in argv], environment, 20)
            else:
                result = self.runner([str(value) for value in argv], capture_output=True,
                                     timeout=20, env=environment)
        except subprocess.TimeoutExpired as error:
            self._revalidate(directory)
            _write(directory / (label + '.stdout'), error.stdout or b'')
            _write(directory / (label + '.stderr'), error.stderr or b'')
            _write(directory / (label + '.outcome.json'),
                   b'{"outcome":"timeout","completion":"uncertain"}')
            raise RuntimeError('native adapter command uncertain') from None
        except CommandCleanupUncertain as error:
            self._revalidate(directory)
            _write(directory / (label + '.stdout'), error.stdout)
            _write(directory / (label + '.stderr'), error.stderr)
            _write(directory / (label + '.outcome.json'),
                   b'{"outcome":"cleanup","completion":"uncertain"}')
            raise RuntimeError('native adapter command uncertain') from None
        except CommandOutputLimit as error:
            self._revalidate(directory)
            _write(directory / (label + '.stdout'), error.stdout)
            _write(directory / (label + '.stderr'), error.stderr)
            _write(directory / (label + '.outcome.json'),
                   b'{"outcome":"output_limit","completion":"uncertain"}')
            raise RuntimeError('native adapter command output uncertain') from None
        self._revalidate(directory)
        if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > MAX_COMMAND_OUTPUT:
            _write(directory / (label + '.stdout'), result.stdout[:MAX_COMMAND_OUTPUT])
            _write(directory / (label + '.stderr'), result.stderr[:MAX_COMMAND_OUTPUT])
            _write(directory / (label + '.outcome.json'),
                   b'{"outcome":"output_limit","completion":"uncertain"}')
            raise RuntimeError('native adapter command output uncertain')
        _write(directory / (label + '.stdout'), result.stdout)
        _write(directory / (label + '.stderr'), result.stderr)
        _write(directory / (label + '.outcome.json'),
               json.dumps({'returncode': result.returncode}, separators=(',', ':')).encode())
        if result.returncode:
            raise RuntimeError('native adapter command failed')
        return result

    def prove(self, requirement):
        operation = requirement.get('operation_id') if isinstance(requirement, dict) else None
        context = self.contexts.pop(operation, None)
        if (context is None or not isinstance(requirement, dict)
                or context['binding'] != {key: requirement.get(key) for key in context['binding']}):
            raise RuntimeError('native adapter forward binding absent')
        for path in (self.litestream, self.config, self.socket_path,
                     self.databases[context['database']], self.evidence):
            self._revalidate(path)
        if hashlib.sha256(self.litestream.read_bytes()).hexdigest() != self.binary_sha256:
            raise RuntimeError('native adapter binary content changed')
        directory = self.evidence / operation
        directory.mkdir(mode=0o700)
        value = directory.lstat()
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
                or value.st_mode & 0o077 or directory.is_symlink()):
            raise RuntimeError('native adapter operation directory differs')
        self.identities[directory] = (value.st_dev, value.st_ino, 'directory')
        database = context['database']
        source = self.databases[database]
        sync = self._command(directory, 'sync', [self.litestream, 'sync', '-socket', self.socket_path,
            '-timeout', '10', '-wait', '-json', source])
        try:
            position = _json(sync.stdout)
            if (not isinstance(position, dict)
                    or set(position) != {'db_path', 'txid', 'replica_txid', 'duration_ms'}
                    or position['db_path'] != str(source)
                    or type(position['txid']) is not int or position['txid'] <= 0
                    or type(position['replica_txid']) is not int
                    or position['replica_txid'] != position['txid']
                    or type(position['duration_ms']) is not int or position['duration_ms'] < 0):
                raise ValueError
        except (TypeError, ValueError, UnicodeDecodeError):
            raise RuntimeError('native adapter sync result differs') from None
        restored = directory / (database + '.restore')
        self._revalidate(self.litestream); self._revalidate(self.config); self._revalidate(source)
        self._command(directory, 'restore', [self.litestream, 'restore', '-config', self.config,
            '-txid', f"{position['txid']:016x}", '-integrity-check', 'none', '-o', restored, source])
        self._revalidate(directory)
        descriptor = os.open(restored, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            value = os.fstat(descriptor)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                    or value.st_nlink != 1 or value.st_size > 256 * 1024 * 1024):
                raise RuntimeError('native adapter restored image differs')
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            identity = value.st_dev, value.st_ino
        finally:
            os.close(descriptor)
        current = restored.lstat()
        if ((current.st_dev, current.st_ino) != identity or restored.is_symlink()
                or self.root not in restored.resolve().parents):
            raise RuntimeError('native adapter restored image identity changed')
        output = directory / (database + '.db')
        self._revalidate(directory)
        os.replace(restored, output)
        folder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
        value = output.lstat()
        if ((value.st_dev, value.st_ino) != identity or value.st_mode & 0o077
                or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1):
            raise RuntimeError('native adapter restored image differs')
        try:
            response = _json(context['response_body'])
            identifiers = response.get('ids') if isinstance(response, dict) else None
            if (not isinstance(identifiers, list) or len(identifiers) != 1
                    or type(identifiers[0]) not in (int, str)
                    or isinstance(identifiers[0], str) and not identifiers[0].isdigit()):
                raise ValueError
            with closing(sqlite3.connect(f'file:{output}?mode=ro', uri=True)) as connection:
                connection.execute('PRAGMA ignore_check_constraints=ON')
                if (connection.execute('PRAGMA integrity_check').fetchone() != ('ok',)
                        or connection.execute('PRAGMA foreign_key_check').fetchall()):
                    raise ValueError
                row = connection.execute('SELECT op_key,payload FROM hat_ops WHERE id=?',
                                         (identifiers[0],)).fetchone()
            expected = context['request_body']
            if row != (expected['op_key'], expected['payload']):
                raise ValueError
        except (sqlite3.Error, TypeError, ValueError, UnicodeDecodeError):
            raise RuntimeError('native adapter restored membership differs') from None
        evidence_id = f"native-{operation}-{database}-{position['txid']}"
        record = {'operation_id': operation, 'request_digest': requirement['request_digest'],
                  'epoch': requirement['epoch'], 'writer_boot': requirement['writer_boot'],
                  'database': database, 'txid': position['txid'],
                  'replica_txid': position['replica_txid'], 'image_verified': True,
                  'evidence_id': evidence_id, 'membership': 'PASS',
                  'image_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
        self._revalidate(directory)
        _write(directory / 'proof.json', json.dumps(record, separators=(',', ':')).encode())
        return {key: record[key] for key in ('operation_id', 'request_digest', 'epoch', 'writer_boot',
                'database', 'txid', 'replica_txid', 'image_verified', 'evidence_id')}


def admit_native(journal, request, adapter):
    """Reject outside the first native slice before creating a kernel intent."""
    adapter.validate_policy(request)
    return admission.admit(journal, request, adapter.forward, adapter.prove)
