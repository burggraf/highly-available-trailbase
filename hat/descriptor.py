"""Descriptor-relative authority for bounded local restore artifacts."""
import hashlib
import os
from pathlib import Path
import stat
import sys


_ID_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size')
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)


def stat_identity(value):
    """Return the complete file identity used at every restore boundary."""
    return tuple(getattr(value, field) for field in _ID_FIELDS)


def close_all(authorities):
    """Close every authority in reverse without hiding an active failure."""
    active = sys.exc_info()[0] is not None
    first = None
    for authority in reversed(authorities):
        try:
            authority.close()
        except BaseException as exc:
            if first is None:
                first = exc
    if first is not None and not active:
        raise first


def _directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _absolute(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('descriptor path traversal is forbidden')
    return path


def _bounded_read(fd, limit):
    before = os.fstat(fd)
    data = bytearray()
    offset = 0
    while len(data) <= limit:
        part = os.pread(fd, min(65536, limit + 1 - len(data)), offset)
        if not part:
            break
        data.extend(part)
        offset += len(part)
    after = os.fstat(fd)
    if len(data) > limit or stat_identity(before) != stat_identity(after) or before.st_size != len(data):
        raise ValueError('descriptor input changed or is oversized')
    raw = bytes(data)
    return raw, hashlib.sha256(raw).hexdigest(), stat_identity(after)


class DescriptorAuthority:
    """Hold and re-resolve every descriptor from ``/`` through one trusted path."""

    def __init__(self, path, trusted_root, trusted_uids, directory=False):
        self.path = _absolute(path)
        self.trusted_root = _absolute(trusted_root)
        try:
            self.path.relative_to(self.trusted_root)
        except ValueError as exc:
            raise ValueError('descriptor path is outside its authorized root') from exc
        self.trusted_uids = frozenset(trusted_uids)
        if not self.trusted_uids:
            raise ValueError('descriptor authority has no trusted owner')
        self._directories = []
        self._file_fd = None
        self._file_identity = None
        self._raw = None
        self.sha256 = None
        self.limit = None
        self._open_directories(self.path if directory or self.path == self.trusted_root else self.path.parent)

    @classmethod
    def open_directory(cls, path, *, trusted_root, trusted_uids):
        authority = cls(path, trusted_root, trusted_uids, directory=True)
        if authority.directory_path != authority.path:
            close_all([authority])
            raise ValueError('descriptor directory path differs')
        return authority

    @classmethod
    def open_file(cls, path, *, trusted_root, trusted_uids, expected_uid=None,
                  expected_gid=None, expected_mode=None, expected_nlink=1,
                  expected_size=None, expected_sha256=None, limit=4 << 20,
                  allow_empty=False):
        authority = cls(path, trusted_root, trusted_uids)
        try:
            authority._open_file(expected_uid, expected_gid, expected_mode, expected_nlink,
                                 expected_size, expected_sha256, limit, allow_empty)
            return authority
        except BaseException:
            close_all([authority])
            raise

    @property
    def directory_path(self):
        return self._directories[-1][0]

    @property
    def directory_fd(self):
        return self._directories[-1][1]

    @property
    def file_fd(self):
        if self._file_fd is None:
            raise ValueError('authority is not a file')
        return self._file_fd

    @property
    def identity(self):
        if self._file_identity is None:
            raise ValueError('authority is not a file')
        return self._file_identity

    def _open_directories(self, target):
        fd = os.open('/', _DIR_FLAGS)
        root_parts = self.trusted_root.parts[1:]
        target_parts = target.parts[1:]
        try:
            current = Path('/')
            self._record_directory(current, fd, len(root_parts) == 0)
            fd = None
            for index, component in enumerate(target_parts, 1):
                parent_fd = self._directories[-1][1]
                child_fd = os.open(component, _DIR_FLAGS, dir_fd=parent_fd)
                current /= component
                self._record_directory(current, child_fd, index >= len(root_parts))
            if current != target:
                raise ValueError('descriptor ancestry differs')
        except OSError as exc:
            if fd is not None: os.close(fd)
            for _, opened, _, _ in reversed(self._directories): os.close(opened)
            self._directories.clear()
            raise ValueError('descriptor ancestry is unsafe') from exc
        except BaseException:
            if fd is not None: os.close(fd)
            for _, opened, _, _ in reversed(self._directories): os.close(opened)
            self._directories.clear()
            raise

    def _record_directory(self, path, fd, trusted):
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('descriptor ancestry is not a directory')
            if trusted and (info.st_uid not in self.trusted_uids or info.st_mode & 0o022):
                raise ValueError('descriptor ancestry is not trusted')
            self._directories.append((path, fd, _directory_identity(info), trusted))
        except BaseException:
            os.close(fd)
            raise

    def _open_file(self, uid, gid, mode, nlink, size, digest, limit, allow_empty):
        try:
            fd = os.open(self.path.name, _FILE_FLAGS, dir_fd=self.directory_fd)
        except OSError as exc:
            raise ValueError('descriptor file is unsafe') from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or uid is not None and info.st_uid != uid
                    or gid is not None and info.st_gid != gid
                    or mode is not None and stat.S_IMODE(info.st_mode) != mode
                    or nlink is not None and info.st_nlink != nlink
                    or size is not None and info.st_size != size
                    or (not allow_empty and info.st_size <= 0)
                    or info.st_size > limit):
                raise ValueError('descriptor file identity is not trusted')
            raw, actual_digest, identity = _bounded_read(fd, limit)
            if digest is not None and actual_digest != digest:
                raise ValueError('descriptor file hash differs')
            self._file_fd = fd
            self._file_identity = identity
            self._raw = raw
            self.sha256 = actual_digest
            self.limit = limit
        except BaseException:
            os.close(fd)
            raise

    def read(self):
        if self._raw is None:
            raise ValueError('authority is not a file')
        return self._raw

    def recheck(self):
        """Check held descriptors and the current namespace against the original chain."""
        for _, fd, identity, _ in self._directories:
            if _directory_identity(os.fstat(fd)) != identity:
                raise ValueError('held descriptor ancestry changed')
        reopened = []
        try:
            fd = os.open('/', _DIR_FLAGS); reopened.append(fd)
            if _directory_identity(os.fstat(fd)) != self._directories[0][2]:
                raise ValueError('descriptor root changed')
            for (_, _, expected, _), component in zip(self._directories[1:], self.directory_path.parts[1:]):
                fd = os.open(component, _DIR_FLAGS, dir_fd=fd); reopened.append(fd)
                if _directory_identity(os.fstat(fd)) != expected:
                    raise ValueError('descriptor ancestry was replaced')
            if self._file_fd is not None:
                raw, digest, identity = _bounded_read(self._file_fd, self.limit)
                if identity != self._file_identity or digest != self.sha256 or raw != self._raw:
                    raise ValueError('held descriptor file changed')
                current = os.open(self.path.name, _FILE_FLAGS, dir_fd=fd)
                reopened.append(current)
                _, current_digest, current_identity = _bounded_read(current, self.limit)
                if current_identity != self._file_identity or current_digest != self.sha256:
                    raise ValueError('descriptor file was replaced')
        except OSError as exc:
            raise ValueError('descriptor namespace changed') from exc
        finally:
            for item in reversed(reopened):
                os.close(item)
        return self

    def copy_to(self, destination, name, *, mode, uid, gid, fsync=None, label='copy'):
        """Exclusive-create a bound copy through a held destination directory fd."""
        if self._file_fd is None or '/' in name or name in ('', '.', '..'):
            raise ValueError('invalid descriptor copy')
        self.recheck(); destination.recheck()
        sync = fsync or (lambda fd, _label, _path: os.fsync(fd))
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      mode, dir_fd=destination.directory_fd)
        try:
            view = memoryview(self._raw)
            while view:
                written = os.write(out, view)
                if written <= 0:
                    raise OSError('short descriptor write')
                view = view[written:]
            os.fchmod(out, mode)
            os.fchown(out, uid, gid)
            sync(out, label + '.file', destination.path / name)
            info = os.fstat(out)
            if (stat.S_IMODE(info.st_mode) != mode or info.st_uid != uid or info.st_gid != gid
                    or info.st_nlink != 1 or info.st_size != len(self._raw)):
                raise ValueError('descriptor destination identity differs')
        finally:
            os.close(out)
        sync(destination.directory_fd, label + '.dir', destination.path)
        copied = type(self).open_file(destination.path / name,
                    trusted_root=destination.trusted_root, trusted_uids=destination.trusted_uids,
                    expected_uid=uid, expected_gid=gid, expected_mode=mode, expected_nlink=1,
                    expected_size=len(self._raw), expected_sha256=self.sha256, limit=self.limit,
                    allow_empty=len(self._raw) == 0)
        try:
            self.recheck(); destination.recheck(); copied.recheck()
        except BaseException:
            close_all([copied])
            raise
        return copied

    def close(self):
        if self._file_fd is not None:
            os.close(self._file_fd)
            self._file_fd = None
        for _, fd, _, _ in reversed(self._directories):
            os.close(fd)
        self._directories.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        close_all([self])
