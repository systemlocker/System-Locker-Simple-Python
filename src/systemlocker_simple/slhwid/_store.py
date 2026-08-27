"""Persistence for the secret-sharing module.

Windows stores values in the registry (HKLM with an HKCU fallback when the
write is denied); everything else uses owner-only files in the platform's
application-support/data directory. All formats are the normative
cross-language ones, so a developer may migrate an application between
System Locker client languages on the same machine.
"""

from __future__ import annotations

import os
import secrets
import struct
import sys
import tempfile
import time
from contextlib import contextmanager

from .core import CorruptHelperError, SLSTORE_PREFIX


_LOCK_FILE = ".slhwid.lock"
_LOCK_HEADER = "SLHwidLockV1"
_LOCK_WAIT_SECONDS = 30
_UNKNOWN_LOCK_GRACE_SECONDS = 120


def _local_lock_directory() -> str:
    return os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local")),
        "SystemLocker",
    )


def _read_lock(path: str) -> tuple[str | None, int | None] | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            contents = handle.read()
    except FileNotFoundError:
        return None
    except OSError:
        return None, None
    lines = contents.splitlines()
    if len(lines) == 3 and lines[0] == _LOCK_HEADER and lines[1].isdigit() and lines[2]:
        return contents, int(lines[1])
    return contents, None


def _process_is_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            # Access denied is conservative: another user's process may own
            # the lock. Any other failure means the PID no longer exists.
            return ctypes.get_last_error() == 5
        try:
            exit_code = ctypes.c_ulong()
            return not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _remove_if_unchanged(path: str, expected: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            contents = handle.read()
    except OSError:
        # A concurrent release or recovery needs no further action.
        pass
        return
    try:
        if contents == expected:
            os.unlink(path)
    except OSError:
        # A concurrent release or recovery needs no further action.
        pass


def _acquire_lock(directory: str):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, _LOCK_FILE)
    contents = f"{_LOCK_HEADER}\n{os.getpid()}\n{secrets.token_hex(16)}\n"
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(contents)
                handle.flush()
            return lambda: _remove_if_unchanged(path, contents)
        except FileExistsError:
            existing = _read_lock(path)
            if existing and existing[0] is not None:
                expected, pid = existing
                stale = pid is not None and not _process_is_alive(pid)
                if pid is None:
                    try:
                        stale = time.time() - os.path.getmtime(path) >= _UNKNOWN_LOCK_GRACE_SECONDS
                    except OSError:
                        stale = False
                if stale:
                    _remove_if_unchanged(path, expected)
                    continue
        except OSError as error:
            raise OSError(f"slhwid: cannot acquire storage lock: {error}") from error
        if time.monotonic() >= deadline:
            raise OSError("slhwid: storage is busy; retry the operation")
        time.sleep(0.05)


class _Store:
    def read_slstore(self) -> bytes | None:
        raise NotImplementedError

    def write_slstore(self, value: bytes) -> None:
        raise NotImplementedError

    def read_helper(self, helper_id: str) -> tuple[bytes, bool]:
        raise NotImplementedError

    def write_helper(self, helper_id: str, blob: bytes) -> None:
        raise NotImplementedError


def _unwrap_slstore(data: bytes) -> bytes:
    if len(data) != len(SLSTORE_PREFIX) + 32:
        raise CorruptHelperError("slhwid: store secret has the wrong size")
    if data[: len(SLSTORE_PREFIX)] != SLSTORE_PREFIX:
        raise CorruptHelperError("slhwid: store secret prefix mismatch")
    return data[len(SLSTORE_PREFIX) :]


class DirStore(_Store):
    """Owner-only files in one directory (every platform)."""

    def __init__(self, directory: str) -> None:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        self._dir = directory

    @contextmanager
    def lock(self):
        release = _acquire_lock(self._dir)
        try:
            yield
        finally:
            release()

    def _path(self, name: str) -> str:
        return os.path.join(self._dir, name)

    def read_slstore(self) -> bytes | None:
        try:
            with open(self._path("slstore.bin"), "rb") as handle:
                return _unwrap_slstore(handle.read())
        except FileNotFoundError:
            return None

    def write_slstore(self, value: bytes) -> None:
        self._write("slstore.bin", SLSTORE_PREFIX + value)

    def read_helper(self, helper_id: str) -> tuple[bytes, bool]:
        try:
            with open(self._path(f"hwid-{helper_id}.bin"), "rb") as handle:
                return handle.read(), True
        except FileNotFoundError:
            return b"", False

    def write_helper(self, helper_id: str, blob: bytes) -> None:
        self._write(f"hwid-{helper_id}.bin", blob)

    def _write(self, name: str, data: bytes) -> None:
        path = self._path(name)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=self._dir)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        os.chmod(path, 0o600)  # tighten pre-existing files too


if sys.platform == "win32":
    import winreg

    _HKLM_SOFTWARE_SYSTEMLOCKER = (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\SystemLocker",
    )
    _HKCU_SOFTWARE_SYSTEMLOCKER = (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\SystemLocker",
    )

    class RegistryStore(_Store):
        """REG_BINARY values under HKLM, falling back to HKCU on denial."""

        def __init__(self) -> None:
            self._lock_dir = _local_lock_directory()
            self._selected_root = None

        @contextmanager
        def lock(self):
            release = _acquire_lock(self._lock_dir)
            try:
                yield
            finally:
                release()

        @staticmethod
        def _read(root, path: str, name: str) -> bytes | None:
            try:
                with winreg.OpenKey(
                    root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                ) as key:
                    value, _ = winreg.QueryValueEx(key, name)
                return bytes(value)
            except OSError:
                return None

        @staticmethod
        def _write(root, path: str, name: str, data: bytes) -> bool:
            try:
                with winreg.CreateKeyEx(
                    root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
                ) as key:
                    winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, data)
                return True
            except OSError:
                return False

        def _select_root(self, helper_name: str = ""):
            """Pin a helper and its mandatory secret to one hive.

            A pair is one generation. Prefer complete HKLM, then complete
            HKCU; partial data is useful only as an explicit corrupt/missing
            generation, never as permission to cross-read the other hive.
            """
            if self._selected_root is not None:
                return self._selected_root
            lm_helper = self._read(*_HKLM_SOFTWARE_SYSTEMLOCKER, helper_name) if helper_name else None
            cu_helper = self._read(*_HKCU_SOFTWARE_SYSTEMLOCKER, helper_name) if helper_name else None
            lm_store = self._read(*_HKLM_SOFTWARE_SYSTEMLOCKER, "SLStore")
            cu_store = self._read(*_HKCU_SOFTWARE_SYSTEMLOCKER, "SLStore")
            if lm_helper is not None and lm_store is not None or (not helper_name and lm_store is not None):
                self._selected_root = _HKLM_SOFTWARE_SYSTEMLOCKER
            elif cu_helper is not None and cu_store is not None or (not helper_name and cu_store is not None):
                self._selected_root = _HKCU_SOFTWARE_SYSTEMLOCKER
            elif lm_helper is not None or lm_store is not None:
                self._selected_root = _HKLM_SOFTWARE_SYSTEMLOCKER
            elif cu_helper is not None or cu_store is not None:
                self._selected_root = _HKCU_SOFTWARE_SYSTEMLOCKER
            return self._selected_root

        def _write_selected(self, name: str, data: bytes) -> None:
            root = self._select_root()
            if root is not None and self._write(*root, name, data):
                return
            for candidate in (_HKLM_SOFTWARE_SYSTEMLOCKER, _HKCU_SOFTWARE_SYSTEMLOCKER):
                if self._write(*candidate, name, data):
                    self._selected_root = candidate
                    return
            raise OSError("slhwid: registry write failed")

        def read_slstore(self) -> bytes | None:
            root = self._select_root()
            if root is not None:
                data = self._read(*root, "SLStore")
                if data is not None:
                    return _unwrap_slstore(data)
            return None

        def write_slstore(self, value: bytes) -> None:
            blob = SLSTORE_PREFIX + value
            self._write_selected("SLStore", blob)

        def read_helper(self, helper_id: str) -> tuple[bytes, bool]:
            name = f"HWID-{helper_id}"
            root = self._select_root(name)
            if root is not None:
                blob = self._read(*root, name)
                if blob is not None:
                    return blob, True
            return b"", False

        def write_helper(self, helper_id: str, blob: bytes) -> None:
            name = f"HWID-{helper_id}"
            self._write_selected(name, blob)


def default_store(override: str = "") -> _Store:
    if override:
        return DirStore(override)
    if sys.platform == "win32":
        return RegistryStore()
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        directory = os.path.join(home, "Library", "Application Support", "SystemLocker")
    else:
        directory = os.path.join(
            os.environ.get("XDG_DATA_HOME", os.path.join(home, ".local", "share")),
            "systemlocker",
        )
    return DirStore(directory)
