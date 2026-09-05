"""Tests for the trusted logging edge client (secretskit.log_edge)."""

import base64
import http.server
import json
import threading
import time

import pytest

from cryptography.hazmat.primitives import serialization

from secretskit import FileKeyProvider, Decryptor, generate_identity, save_identity
from secretskit._manifest import generate_signing_key, serialize_verification_key
from secretskit import _signing
from secretskit.log_edge import LogEdgeClient, LogEdgeConfig

_PEM = serialization.Encoding.PEM
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


class _LogEdgeServer:
    """Minimal /keys + /log stand-in: returns logger keys, records POSTs."""

    def __init__(self, logger_kem_pub, logger_x_pub):
        self.posts = []
        self._logger_kem_pub = logger_kem_pub
        self._logger_x_pub = logger_x_pub
        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def _handler(self, *args):
        H = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _check_auth(self):
                # Accept the static bearer token OR ML-DSA transport auth
                # (X-Spoke-ID present) — mirrors the LogSink's dual auth.
                if self.headers.get("Authorization") == "Bearer t":
                    return True
                return bool(self.headers.get("X-Spoke-ID"))

            def do_GET(self):
                if self.path != "/keys":
                    self.send_response(404)
                    self.end_headers()
                    return
                if not self._check_auth():
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps({
                    "id": "logsink-1",
                    "kem_pub": H._logger_kem_pub,
                    "x_pub": H._logger_x_pub,
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(length)
                H.posts.append((self.path, self.headers.get("Authorization"), data))
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        return Handler(*args)

    def stop(self):
        self._srv.shutdown()


def _pem_public(key) -> str:
    return base64.b64encode(key.public_bytes(_PEM, _SPKI)).decode("ascii")


def _fixtures(tmp_path):
    sender_kd = tmp_path / "sender"
    sender = generate_identity("server-1")
    save_identity(sender, sender_kd)
    sign_key = generate_signing_key()
    sign_pem = sender_kd / "server-1.sign.pem"
    sign_pem.write_bytes(
        sign_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    logger_kd = tmp_path / "logger"
    logger = generate_identity("logsink-1")
    save_identity(logger, logger_kd)
    return sender, sign_key, sign_pem, logger, logger_kd


def test_prompt_record_roundtrip(tmp_path):
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(
                url=srv.url,
                token="t",
                sender_id="server-1",
                signing_key=str(sign_pem),
                logger_id="logsink-1",
            ),
            strict=True,
        )
        client.send_prompt(
            "rid-1", "total revenue per product category",
            endpoint="completion", call="invoke", model="p4",
        )
        assert len(srv.posts) == 1
        path, auth, body = srv.posts[0]
        assert path == "/log"
        # A sender with a signing key authenticates via ML-DSA transport auth,
        # not the static bearer token (transport-auth feature).
        assert auth is None
        req = json.loads(body)
        assert req["kind"] == "prompt"

        dec = Decryptor(provider=FileKeyProvider(logger_kd, "logsink-1"))
        signed_doc = dec.decrypt_chunk(base64.b64decode(req["envelope"]))
        out = _signing.verify(signed_doc, sign_key.public_key())
        assert out["user_id"] == "server-1"
        assert out["request_id"] == "rid-1"
        record = json.loads(out["data"])
        assert record["kind"] == "prompt"
        assert record["prompt"] == "total revenue per product category"
        assert record["endpoint"] == "completion"
        assert record["call"] == "invoke"
        assert record["model"] == "p4"
    finally:
        srv.stop()


def test_response_record_roundtrip(tmp_path):
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(url=srv.url, token="t", sender_id="spoke-1", signing_key=str(sign_pem)),
            strict=True,
        )
        client.send_response("rid-2", "the answer", endpoint="completion")
        _, _, body = srv.posts[0]
        req = json.loads(body)
        dec = Decryptor(provider=FileKeyProvider(logger_kd, "logsink-1"))
        signed_doc = dec.decrypt_chunk(base64.b64decode(req["envelope"]))
        out = _signing.verify(signed_doc, sign_key.public_key())
        record = json.loads(out["data"])
        assert record["kind"] == "response"
        assert record["request_id"] == "rid-2"
        assert record["response"] == "the answer"
    finally:
        srv.stop()


def test_response_record_bytes_payload(tmp_path):
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(url=srv.url, token="t", sender_id="spoke-1", signing_key=str(sign_pem)),
            strict=True,
        )
        client.send_response("rid-bytes", b'data: {"tok":"hel"}\n\n', endpoint="completion")
        _, _, body = srv.posts[0]
        req = json.loads(body)
        dec = Decryptor(provider=FileKeyProvider(logger_kd, "logsink-1"))
        signed_doc = dec.decrypt_chunk(base64.b64decode(req["envelope"]))
        out = _signing.verify(signed_doc, sign_key.public_key())
        record = json.loads(out["data"])
        assert record["response"] == 'data: {"tok":"hel"}\n\n'
    finally:
        srv.stop()


def test_signing_override_in_memory(tmp_path):
    """A caller-supplied loaded key (e.g. from BootKeyProvider) skips file IO."""
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(url=srv.url, token="t", sender_id="server-1"),
            strict=True, signing=sign_key,  # no LOG_EDGE_SIGNING_KEY set
        )
        client.send_prompt("rid-sig", "hi")
        _, _, body = srv.posts[0]
        dec = Decryptor(provider=FileKeyProvider(logger_kd, "logsink-1"))
        signed_doc = dec.decrypt_chunk(base64.b64decode(json.loads(body)["envelope"]))
        out = _signing.verify(signed_doc, sign_key.public_key())
        assert json.loads(out["data"])["prompt"] == "hi"
    finally:
        srv.stop()


def test_background_delivery_does_not_block(tmp_path):
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(url=srv.url, token="t", sender_id="server-1", signing_key=str(sign_pem)),
            strict=False, background=True,
        )
        client.send_prompt("rid-bg", "hi")  # must return without waiting on delivery
        deadline = time.time() + 5
        while time.time() < deadline and len(srv.posts) == 0:
            time.sleep(0.05)
        assert len(srv.posts) == 1
        _, _, body = srv.posts[0]
        assert json.loads(body)["kind"] == "prompt"
    finally:
        srv.stop()


def test_disabled_when_no_url(tmp_path):
    client = LogEdgeClient(LogEdgeConfig(url=""))
    assert client.enabled is False
    client.send_prompt("x", "y")  # must be a no-op


def test_fail_soft_on_network_error(tmp_path):
    _, _, sign_pem, _, _ = _fixtures(tmp_path)
    client = LogEdgeClient(
        LogEdgeConfig(url="http://127.0.0.1:1", token="t", sender_id="server-1", signing_key=str(sign_pem)),
        strict=False,
    )
    client.send_prompt("x", "y")  # connection refused; must not raise


def test_strict_raises_on_network_error(tmp_path):
    import pytest

    _, _, sign_pem, _, _ = _fixtures(tmp_path)
    client = LogEdgeClient(
        LogEdgeConfig(url="http://127.0.0.1:1", token="t", sender_id="server-1", signing_key=str(sign_pem)),
        strict=True,
    )
    with pytest.raises(Exception):
        client.send_prompt("x", "y")


def test_from_env(tmp_path):
    _, _, sign_pem, _, _ = _fixtures(tmp_path)
    os_environ = {
        "LOG_EDGE_URL": "http://logsink:8086",
        "LOGSINK_ACCESS_TOKEN": "tok",
        "LOG_EDGE_SENDER_ID": "server-1",
        "LOG_EDGE_SIGNING_KEY": str(sign_pem),
    }
    cfg = LogEdgeConfig.from_env(os_environ)
    assert cfg.url == "http://logsink:8086"
    assert cfg.token == "tok"
    assert cfg.sender_id == "server-1"
    assert cfg.logger_id == "logsink-1"
    assert LogEdgeClient(cfg).enabled


def test_send_record_endpoint_roundtrip(tmp_path):
    """Generic send_record ships an arbitrary kind=endpoint record intact."""
    sender, sign_key, sign_pem, logger, logger_kd = _fixtures(tmp_path)
    srv = _LogEdgeServer(_pem_public(logger.kem.public_key()), _pem_public(logger.x.public_key()))
    try:
        client = LogEdgeClient(
            LogEdgeConfig(url=srv.url, token="t", sender_id="builder-1", signing_key=str(sign_pem)),
            strict=True,
        )
        client.send_record({
            "kind": "endpoint",
            "request_id": "rid-end-1",
            "client_user_id": "user-42",
            "session_id": "sess-1",
            "endpoint": "api/inference/db-map/v3",
            "builder_id": "builder-1",
            "ts": "2026-09-05T10:15:30.123Z",
            "query": "total revenue per product",
            "llm_calls": [
                {"path": "identify_v4_reason", "model": "p4",
                 "prompt": "Is the orders table needed?", "response": "yes",
                 "ts": "2026-09-05T10:15:30.123Z", "tokens_in": 10, "tokens_out": 1},
            ],
            "parsed": {"table_names": ["orders"]},
            "error": None,
        })
        assert len(srv.posts) == 1
        path, _, body = srv.posts[0]
        assert path == "/log"
        req = json.loads(body)
        assert req["kind"] == "endpoint"

        dec = Decryptor(provider=FileKeyProvider(logger_kd, "logsink-1"))
        signed_doc = dec.decrypt_chunk(base64.b64decode(req["envelope"]))
        out = _signing.verify(signed_doc, sign_key.public_key())
        assert out["request_id"] == "rid-end-1"
        record = json.loads(out["data"])
        assert record["kind"] == "endpoint"
        assert record["client_user_id"] == "user-42"
        assert record["session_id"] == "sess-1"
        assert record["parsed"] == {"table_names": ["orders"]}
        assert record["llm_calls"][0]["path"] == "identify_v4_reason"
        assert record["llm_calls"][0]["response"] == "yes"
    finally:
        srv.stop()


def test_send_record_requires_kind_and_request_id(tmp_path):
    _, sign_key, _, _, _ = _fixtures(tmp_path)
    client = LogEdgeClient(
        LogEdgeConfig(url="http://logsink:8086", token="t", sender_id="builder-1"),
        strict=True, signing=sign_key,
    )
    with pytest.raises(ValueError):
        client.send_record({"session_id": "x"})  # no kind
    with pytest.raises(ValueError):
        client.send_record({"kind": "endpoint"})  # no request_id
    with pytest.raises(TypeError):
        client.send_record("not-a-dict")
