"""Memory hygiene helpers for hardened edges (§9.5).

Best-effort POSIX memory hardening: disable core dumps and mlock key material
into RAM so a compromised or crashing machine leaks as little as possible.
Every function is a safe no-op when the underlying call is unavailable
(non-POSIX, constrained containers, etc.), so callers can use them freely.
"""

import ctypes
import resource

try:
    from resource import RLIMIT_CORE  # noqa: F401 - POSIX only
except ImportError:  # pragma: no cover - non-POSIX
    RLIMIT_CORE = None


def disable_core_dumps() -> bool:
    """Set RLIMIT_CORE to zero so a crash never dumps process memory.

    Returns True if the limit was applied, False if the platform doesn't
    support it (best-effort).
    """
    if RLIMIT_CORE is None:
        return False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, OSError):
        return False


_libc = None


def _get_libc():
    """Load libc once for mlock/munlock; False if unavailable."""
    global _libc
    if _libc is None:
        for name in ("libc.so.6", "libc.so", "libc.dylib"):
            try:
                _libc = ctypes.CDLL(name, use_errno=True)
                break
            except OSError:
                continue
        else:
            _libc = False
    return _libc or None


def _memlock(buf: bytearray, lock: bool) -> bool:
    libc = _get_libc()
    if libc is None or not buf:
        return False
    try:
        arr = (ctypes.c_char * len(buf)).from_buffer(buf)
        fn = libc.mlock if lock else libc.munlock
        return fn(ctypes.addressof(arr), len(buf)) == 0
    except (ctypes.ArgumentError, OSError):
        return False


def mlock_memory(buf: bytearray) -> bool:
    """Lock ``buf`` into RAM (best-effort). Requires a writable buffer."""
    return _memlock(buf, lock=True)


def munlock_memory(buf: bytearray) -> bool:
    """Unlock a buffer previously locked with :func:`mlock_memory`."""
    return _memlock(buf, lock=False)


def wipe(buf: bytearray) -> None:
    """Zero a writable byte buffer (best-effort key sanitisation)."""
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except (TypeError, OSError):
        pass
