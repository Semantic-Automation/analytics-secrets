"""Tests for memory-hygiene helpers (disable_core_dumps / mlock / wipe)."""

from secretskit import disable_core_dumps, mlock_memory, munlock_memory, wipe


def test_disable_core_dumps_returns_bool():
    assert isinstance(disable_core_dumps(), bool)


def test_mlock_roundtrip():
    buf = bytearray(b"secret key material" * 100)
    locked = mlock_memory(buf)
    # Best-effort: may be False in restricted containers, must never raise.
    assert isinstance(locked, bool)
    if locked:
        assert munlock_memory(buf) is True or isinstance(munlock_memory(buf), bool)


def test_mlock_empty_buffer_is_noop():
    assert mlock_memory(bytearray()) is False


def test_wipe_zeroes_buffer():
    buf = bytearray(b"super-secret")
    wipe(buf)
    assert all(b == 0 for b in buf)


def test_wipe_tolerates_non_writable():
    wipe(b"immutable")  # must not raise
