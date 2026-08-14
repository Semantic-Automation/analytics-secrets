"""Streaming tests: one envelope per yield, concatenated and fragmented."""

import io

import pytest

from secretskit import DecryptError, Decryptor, Encryptor, FileKeyProvider, generate_identity, save_identity, save_peer


@pytest.fixture()
def pair(tmp_path):
    hub_dir = tmp_path / "hub"
    spoke_dir = tmp_path / "spoke"
    hub = generate_identity("hub")
    spoke = generate_identity("spoke-1")
    save_identity(hub, hub_dir)
    save_identity(spoke, spoke_dir)
    save_peer(spoke, hub_dir)
    save_peer(hub, spoke_dir)
    enc = Encryptor(provider=FileKeyProvider(hub_dir, "hub"))
    dec = Decryptor(provider=FileKeyProvider(spoke_dir, "spoke-1"))
    return enc, dec


def test_chunk_roundtrip(pair):
    enc, dec = pair
    blob = enc.encrypt_chunk(b"hello")
    assert dec.decrypt_chunk(blob) == b"hello"


def test_each_yield_is_own_envelope(pair):
    """Simulates the server streaming: one envelope per yield statement."""
    enc, dec = pair
    yields = [b"To", b"tal", b" rev", b"enue"]
    envelopes = [enc.encrypt_chunk(y) for y in yields]
    assert len(envelopes) == len(yields)
    for y, env in zip(yields, envelopes):
        assert dec.decrypt_chunk(env) == y


def test_concatenated_stream_in_order(pair):
    enc, dec = pair
    yields = [f"chunk-{i}".encode() for i in range(50)]
    stream = b"".join(enc.encrypt_chunk(y) for y in yields)
    assert list(dec.iter_chunks([stream])) == yields


def test_fragmented_network_stream(pair):
    """Fragments can be split arbitrarily across envelope boundaries."""
    enc, dec = pair
    yields = [b"a" * 3, b"b" * 100, b"c" * 2000, b"d" * 5]
    stream = b"".join(enc.encrypt_chunk(y) for y in yields)
    fragments = [stream[i : i + 7] for i in range(0, len(stream), 7)]
    assert list(dec.iter_chunks(fragments)) == yields


def test_iter_chunks_generator(pair):
    enc, dec = pair
    yields = [b"g%d" % i for i in range(10)]
    stream = b"".join(enc.encrypt_chunk(y) for y in yields)
    assert list(dec.iter_chunks(iter([stream]))) == yields


def test_iter_chunks_file_like(pair):
    enc, dec = pair
    yields = [b"file-chunk-%d" % i for i in range(10)]
    stream = b"".join(enc.encrypt_chunk(y) for y in yields)
    assert list(dec.iter_chunks(io.BytesIO(stream))) == yields


def test_iter_chunks_empty_stream(pair):
    _, dec = pair
    assert list(dec.iter_chunks([b""])) == []
    assert list(dec.iter_chunks([])) == []


def test_truncated_stream_fails(pair):
    enc, dec = pair
    stream = enc.encrypt_chunk(b"payload")
    with pytest.raises(DecryptError):
        list(dec.iter_chunks([stream[: len(stream) // 2]]))


def test_corrupt_envelope_in_stream_fails(pair):
    enc, dec = pair
    good = enc.encrypt_chunk(b"fine")
    bad = bytearray(enc.encrypt_chunk(b"bad"))
    bad[-1] ^= 0xFF
    with pytest.raises(DecryptError):
        list(dec.iter_chunks([good + bytes(bad)]))
