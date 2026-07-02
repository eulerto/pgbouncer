"""
Tests for OAuth client authentication.

libpq cannot easily drive the OAUTHBEARER handshake, so these tests speak the
PostgreSQL wire protocol directly with a small raw client.  PgBouncer is
configured with the example validator module in test/oauth_validator.c, which
resolves bearer tokens against a flat file.
"""

import socket
import struct
import subprocess

import pytest

from .utils import OAUTH_SUPPORT, TEST_DIR

pytestmark = pytest.mark.skipif(
    not OAUTH_SUPPORT, reason="PgBouncer built without --with-oauth or -Doauth"
)

KVSEP = b"\x01"
PROTOCOL_VERSION_3 = 196608


def _startup_message(user, database):
    body = struct.pack("!I", PROTOCOL_VERSION_3)
    for key, value in (("user", user), ("database", database)):
        body += key.encode() + b"\x00" + value.encode() + b"\x00"
    body += b"\x00"
    return struct.pack("!I", len(body) + 4) + body


def oauth_initial_response(token):
    """OAUTHBEARER client initial response carrying a bearer token."""
    return b"n,," + KVSEP + b"auth=Bearer " + token.encode() + KVSEP + KVSEP


def oauth_initial_response_no_token():
    """OAUTHBEARER client initial response without a token (discovery)."""
    return b"n,," + KVSEP + b"auth=" + KVSEP + KVSEP


class RawClient:
    """A minimal PostgreSQL wire-protocol client for the OAUTHBEARER exchange."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(10)
        self.buf = b""

    def _recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("server closed connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_message(self):
        typ = self._recv_exact(1)
        length = struct.unpack("!I", self._recv_exact(4))[0]
        return typ, self._recv_exact(length - 4)

    def send_startup(self, user, database):
        self.sock.sendall(_startup_message(user, database))

    def send_sasl_initial(self, mechanism, data):
        body = mechanism.encode() + b"\x00" + struct.pack("!i", len(data)) + data
        self.sock.sendall(b"p" + struct.pack("!I", len(body) + 4) + body)

    def send_sasl_response(self, data):
        self.sock.sendall(b"p" + struct.pack("!I", len(data) + 4) + data)

    def close(self):
        self.sock.close()


def _parse_error(body):
    fields = {}
    for part in body.split(b"\x00"):
        if part:
            fields[chr(part[0])] = part[1:].decode(errors="replace")
    return fields.get("M", "")


def oauth_exchange(bouncer, user, database, initial_response):
    """
    Perform StartupMessage + the OAUTHBEARER SASL exchange and return a dict
    describing the outcome: whether AuthenticationOk/ReadyForQuery were seen,
    any discovery challenge (bytes), and any error message.
    """
    result = {"ok": False, "ready": False, "challenge": None, "error": None}
    client = RawClient(bouncer.host, bouncer.port)
    try:
        client.send_startup(user, database)

        typ, body = client.read_message()
        assert typ == b"R", f"expected AuthenticationSASL, got {typ!r}"
        code = struct.unpack("!I", body[:4])[0]
        assert code == 10, f"expected SASL (10), got {code}"
        mechs = [m.decode() for m in body[4:].split(b"\x00") if m]
        assert "OAUTHBEARER" in mechs, mechs

        client.send_sasl_initial("OAUTHBEARER", initial_response)

        while True:
            try:
                typ, body = client.read_message()
            except ConnectionError:
                break
            if typ == b"R":
                code = struct.unpack("!I", body[:4])[0]
                if code == 11:  # AuthenticationSASLContinue (challenge)
                    result["challenge"] = body[4:]
                    client.send_sasl_response(KVSEP)
                elif code == 0:  # AuthenticationOk
                    result["ok"] = True
            elif typ == b"E":  # ErrorResponse
                result["error"] = _parse_error(body)
                break
            elif typ == b"Z":  # ReadyForQuery
                result["ready"] = True
                break
        return result
    finally:
        client.close()


def build_validator(tmp_path):
    """Compile the example validator module to a shared object."""
    so_path = tmp_path / "oauth_validator.so"
    subprocess.run(
        [
            "cc",
            "-shared",
            "-fPIC",
            f"-I{TEST_DIR / '..' / 'include'}",
            "-o",
            str(so_path),
            str(TEST_DIR / "oauth_validator.c"),
        ],
        check=True,
    )
    return so_path


@pytest.fixture
async def oauth_bouncer(bouncer, pg, tmp_path, monkeypatch):
    """A PgBouncer configured for OAUTHBEARER auth with the example validator.

    The token file maps "validtoken" to the role "oauthuser" and
    "mismatchtoken" to a different identity.
    """
    validator = build_validator(tmp_path)

    tokens = tmp_path / "tokens.txt"
    tokens.write_text("validtoken oauthuser\nmismatchtoken otheruser\n")
    monkeypatch.setenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS", str(tokens))

    # A role PgBouncer can log in to Postgres as (server-side auth is trust in
    # the test HBA); it also needs an auth_file entry so it is not mock-authed.
    pg.sql("drop role if exists oauthuser")
    pg.sql("create user oauthuser")
    with bouncer.auth_path.open("a") as f:
        f.write('"oauthuser" "unused"\n')

    bouncer.write_ini("auth_type = oauth")
    bouncer.write_ini(f"oauth_validator_library = {validator}")
    bouncer.write_ini("oauth_issuer = https://issuer.example.com")
    bouncer.write_ini("oauth_scope = openid email")
    await bouncer.restart()

    yield bouncer


async def test_oauth_validator_loaded(oauth_bouncer):
    # The module is loaded once at startup, which the fixture's restart already
    # triggered, so check the log file directly.
    assert "loaded OAuth validator module" in oauth_bouncer.log_path.read_text()


async def test_oauth_valid_token(oauth_bouncer):
    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("validtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_bad_token(oauth_bouncer):
    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("wrongtoken")
    )
    assert result["ok"] is False
    assert result["error"] is not None
    assert "OAuth authentication failed" in result["error"]


async def test_oauth_identity_mismatch(oauth_bouncer):
    # Token is valid, but its identity ("otheruser") differs from the login role.
    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("mismatchtoken")
    )
    assert result["ok"] is False
    assert result["error"] is not None
    assert "does not match requested user" in result["error"]


async def test_oauth_delegate_ident_mapping(oauth_bouncer):
    # With delegation on, the module's verdict is trusted and the identity
    # check is skipped, so a mismatching authn_id still logs in.
    oauth_bouncer.write_ini("oauth_delegate_ident_mapping = 1")
    await oauth_bouncer.restart()

    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("mismatchtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_discovery_challenge(oauth_bouncer):
    # No token: PgBouncer answers with a discovery challenge, then fails the
    # exchange once the client acknowledges it.
    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response_no_token()
    )
    assert result["challenge"] is not None
    challenge = result["challenge"].decode()
    assert "https://issuer.example.com/.well-known/openid-configuration" in challenge
    assert "openid email" in challenge
    assert result["error"] is not None
    assert "OAuth bearer token required" in result["error"]
