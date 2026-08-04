"""
Tests for OAuth client authentication.

libpq cannot easily drive the OAUTHBEARER handshake, so these tests speak the
PostgreSQL wire protocol directly with a small raw client.  PgBouncer is
configured with the example validator module in test/oauth_validator.c, which
resolves bearer tokens against a flat file.
"""

import asyncio
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


def build_validator(tmp_path, name=None):
    """Compile the example validator module to a shared object.

    With a name, the module is built declaring that name instead of "example",
    which gives the tests a second, distinctly named validator to load.
    """
    so_path = tmp_path / f"oauth_validator_{name or 'example'}.so"
    cmd = [
        "cc",
        "-shared",
        "-fPIC",
        f"-I{TEST_DIR / '..' / 'include'}",
    ]
    if name:
        cmd.append(f'-DVALIDATOR_NAME="{name}"')
    cmd += ["-o", str(so_path), str(TEST_DIR / "oauth_validator.c")]
    subprocess.run(cmd, check=True)
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
    bouncer.write_ini(f"oauth_validator_libraries = {validator}")
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


async def test_oauth_validator_timeout_setting(oauth_bouncer):
    # The cooperative validation deadline is configurable and reloadable, and
    # setting it must not disturb a normal (fast) validation.
    oauth_bouncer.write_ini("oauth_validator_timeout = 3")
    oauth_bouncer.admin("reload")
    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("validtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_validator_worker_pool(oauth_bouncer):
    # With a pool of workers, a mix of accepted/rejected tokens across the ring
    # must each reach the right client (exercises the shared claim index and
    # the out-of-order reap/reclaim in oauth_poll()).
    oauth_bouncer.write_ini("oauth_validator_workers = 4")
    await oauth_bouncer.restart()
    assert "number of OAuth validation workers: 4" in oauth_bouncer.log_path.read_text()

    for token, expect_ok in [
        ("validtoken", True),
        ("wrongtoken", False),
        ("validtoken", True),
        ("mismatchtoken", False),
    ]:
        result = oauth_exchange(
            oauth_bouncer, "oauthuser", "p0a", oauth_initial_response(token)
        )
        assert result["ok"] is expect_ok, (token, result)


# -------------------------------------------------------------------
# oauth as an HBA method with per-line options and pg_ident usermaps.
# -------------------------------------------------------------------


def _hba_path(bouncer):
    return bouncer.config_dir / "oauth_hba.conf"


def _ident_path(bouncer):
    return bouncer.config_dir / "oauth_ident.conf"


async def set_hba(bouncer, hba_line, ident=""):
    """Rewrite the oauth HBA (and ident) files and reload PgBouncer."""
    _hba_path(bouncer).write_text(hba_line + "\n")
    _ident_path(bouncer).write_text(ident)
    bouncer.admin("reload")


@pytest.fixture
async def oauth_hba_bouncer(bouncer, pg, tmp_path, monkeypatch):
    """PgBouncer with auth_type=hba selecting oauth through auth_hba_file.

    Shares the validator/token/role setup with oauth_bouncer, but the method
    and its per-line options come from the HBA file so the tests can exercise
    per-line issuer/scope/delegate_ident_mapping and map=.  The global
    oauth_issuer/oauth_scope are set to distinctive values so a test can prove
    a per-line option actually overrides them.
    """
    validator = build_validator(tmp_path)

    tokens = tmp_path / "tokens.txt"
    tokens.write_text("validtoken oauthuser\nmismatchtoken otheruser\n")
    monkeypatch.setenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS", str(tokens))

    pg.sql("drop role if exists oauthuser")
    pg.sql("create user oauthuser")
    with bouncer.auth_path.open("a") as f:
        f.write('"oauthuser" "unused"\n')

    # A benign starting rule so the files exist before the first (re)start.
    _hba_path(bouncer).write_text("host all all all oauth\n")
    _ident_path(bouncer).write_text("")

    bouncer.write_ini("auth_type = hba")
    bouncer.write_ini(f"oauth_validator_libraries = {validator}")
    bouncer.write_ini("oauth_issuer = https://global-issuer.example.com")
    bouncer.write_ini("oauth_scope = global-scope")
    bouncer.write_ini(f"auth_hba_file = {_hba_path(bouncer)}")
    bouncer.write_ini(f"auth_ident_file = {_ident_path(bouncer)}")
    await bouncer.restart()

    yield bouncer


async def test_oauth_hba_valid_token(oauth_hba_bouncer):
    await set_hba(oauth_hba_bouncer, "host all all all oauth")
    result = oauth_exchange(
        oauth_hba_bouncer, "oauthuser", "p0a", oauth_initial_response("validtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_hba_per_line_issuer_scope(oauth_hba_bouncer):
    # The per-line issuer/scope must override the (distinct) globals in the
    # discovery challenge.
    await set_hba(
        oauth_hba_bouncer,
        'host all all all oauth issuer="https://line-issuer.example.com" scope="line scope"',
    )
    result = oauth_exchange(
        oauth_hba_bouncer, "oauthuser", "p0a", oauth_initial_response_no_token()
    )
    assert result["challenge"] is not None
    challenge = result["challenge"].decode()
    assert (
        "https://line-issuer.example.com/.well-known/openid-configuration" in challenge
    )
    assert "line scope" in challenge
    # The globals must not leak through.
    assert "global-issuer" not in challenge
    assert "global-scope" not in challenge


async def test_oauth_hba_per_line_delegate(oauth_hba_bouncer):
    # delegate_ident_mapping=1 on the line trusts the module, so a mismatching
    # identity still logs in.
    await set_hba(oauth_hba_bouncer, "host all all all oauth delegate_ident_mapping=1")
    result = oauth_exchange(
        oauth_hba_bouncer, "oauthuser", "p0a", oauth_initial_response("mismatchtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_hba_usermap_match(oauth_hba_bouncer):
    # The token proves identity "otheruser"; the map translates that to the
    # requested role "oauthuser", so login succeeds.
    await set_hba(
        oauth_hba_bouncer,
        "host all all all oauth map=mymap",
        ident="mymap otheruser oauthuser\n",
    )
    result = oauth_exchange(
        oauth_hba_bouncer, "oauthuser", "p0a", oauth_initial_response("mismatchtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True
    assert result["ready"] is True


async def test_oauth_hba_usermap_no_match(oauth_hba_bouncer):
    # The map has no entry for identity "otheruser" -> "oauthuser".
    await set_hba(
        oauth_hba_bouncer,
        "host all all all oauth map=mymap",
        ident="mymap someoneelse oauthuser\n",
    )
    result = oauth_exchange(
        oauth_hba_bouncer, "oauthuser", "p0a", oauth_initial_response("mismatchtoken")
    )
    assert result["ok"] is False
    assert result["error"] is not None
    assert "does not match requested user" in result["error"]


async def test_oauth_hba_map_delegate_conflict(oauth_hba_bouncer):
    # map and delegate_ident_mapping are mutually exclusive; the login is
    # rejected before the SASL exchange even begins.
    await set_hba(
        oauth_hba_bouncer,
        "host all all all oauth map=mymap delegate_ident_mapping=1",
        ident="mymap otheruser oauthuser\n",
    )
    client = RawClient(oauth_hba_bouncer.host, oauth_hba_bouncer.port)
    try:
        client.send_startup("oauthuser", "p0a")
        typ, body = client.read_message()
        assert typ == b"E", f"expected ErrorResponse, got {typ!r}"
        assert "invalid oauth options" in _parse_error(body)
    finally:
        client.close()


# -------------------------------------------------------------------
# Custom configuration sections and selecting among several modules.
# -------------------------------------------------------------------


async def run_pgbouncer_expecting_failure(bouncer):
    """Start PgBouncer in the foreground, expecting it to refuse the config.

    Returns everything it said, on either stream and in its log file.
    """
    proc = await asyncio.create_subprocess_exec(
        *bouncer.base_command(),
        str(bouncer.ini_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    assert proc.returncode != 0
    return stdout.decode() + stderr.decode() + bouncer.log_path.read_text()


async def test_oauth_module_config_section(oauth_bouncer, tmp_path, monkeypatch):
    # The module reads its token file from [oauth:example] instead of the
    # environment, which only works if the section reached it intact.  The
    # section is appended last: everything after it belongs to that section.
    monkeypatch.delenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS")
    oauth_bouncer.write_ini("[oauth:example]")
    oauth_bouncer.write_ini(f"tokens = {tmp_path / 'tokens.txt'}")
    await oauth_bouncer.restart()

    log = oauth_bouncer.log_path.read_text()
    assert 'loaded OAuth validator module "example"' in log
    assert "(1 option(s))" in log

    result = oauth_exchange(
        oauth_bouncer, "oauthuser", "p0a", oauth_initial_response("validtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True


async def test_oauth_module_config_unknown_option(oauth_bouncer, tmp_path):
    # PgBouncer does not know what a module's keys mean, so it is the module
    # that rejects a typo -- and a rejected startup_cb is fatal.
    await oauth_bouncer.stop()
    oauth_bouncer.write_ini("[oauth:example]")
    oauth_bouncer.write_ini("bogus = 1")

    output = await run_pgbouncer_expecting_failure(oauth_bouncer)
    assert 'unrecognized option "bogus"' in output
    assert "failed to start" in output


async def test_oauth_module_config_unclaimed_section(oauth_bouncer, tmp_path):
    # A section no loaded module answers to is a typo in the name; it cannot be
    # detected while parsing (modules load later), so it is warned about.
    oauth_bouncer.write_ini("[oauth:nosuchmodule]")
    oauth_bouncer.write_ini("url = https://example.com")
    await oauth_bouncer.restart()

    log = oauth_bouncer.log_path.read_text()
    assert 'no validator module named "nosuchmodule" is loaded' in log


async def test_oauth_invalid_section_still_fatal(oauth_bouncer):
    # Custom sections are matched by a catch-all entry in the parser; a section
    # that is neither a core nor a custom section must stay a hard error.
    await oauth_bouncer.stop()
    oauth_bouncer.write_ini("[bogussection]")

    output = await run_pgbouncer_expecting_failure(oauth_bouncer)
    assert "unknown section: bogussection" in output


@pytest.fixture
async def oauth_two_validators(oauth_hba_bouncer, tmp_path, monkeypatch):
    """Two validator modules, each with its own token file.

    "example" accepts validtoken (identity oauthuser); "second" accepts
    secondtoken (also oauthuser), so a successful login proves which module
    was consulted.
    """
    monkeypatch.delenv("PGBOUNCER_OAUTH_VALIDATOR_TOKENS")
    first = build_validator(tmp_path)
    second = build_validator(tmp_path, name="second")

    second_tokens = tmp_path / "tokens2.txt"
    second_tokens.write_text("secondtoken oauthuser\n")

    oauth_hba_bouncer.write_ini(f"oauth_validator_libraries = {first}, {second}")
    oauth_hba_bouncer.write_ini("[oauth:example]")
    oauth_hba_bouncer.write_ini(f"tokens = {tmp_path / 'tokens.txt'}")
    oauth_hba_bouncer.write_ini("[oauth:second]")
    oauth_hba_bouncer.write_ini(f"tokens = {second_tokens}")
    await oauth_hba_bouncer.restart()

    yield oauth_hba_bouncer


async def test_oauth_two_validators_loaded(oauth_two_validators):
    log = oauth_two_validators.log_path.read_text()
    assert 'loaded OAuth validator module "example"' in log
    assert 'loaded OAuth validator module "second"' in log


async def test_oauth_validator_selected_per_hba_line(oauth_two_validators):
    await set_hba(oauth_two_validators, "host all all all oauth validator=second")

    # Only the second module knows this token.
    result = oauth_exchange(
        oauth_two_validators, "oauthuser", "p0a", oauth_initial_response("secondtoken")
    )
    assert result["error"] is None, result["error"]
    assert result["ok"] is True

    # The first module's token must not be accepted by the second.
    result = oauth_exchange(
        oauth_two_validators, "oauthuser", "p0a", oauth_initial_response("validtoken")
    )
    assert result["ok"] is False
    assert "OAuth authentication failed" in result["error"]


async def test_oauth_validator_unknown_name(oauth_two_validators):
    # The HBA file is parsed before modules are loaded, so a bad name can only
    # be caught at login time -- and it must fail the login, not fall back.
    await set_hba(oauth_two_validators, "host all all all oauth validator=nosuch")

    client = RawClient(oauth_two_validators.host, oauth_two_validators.port)
    try:
        client.send_startup("oauthuser", "p0a")
        typ, body = client.read_message()
        assert typ == b"E", f"expected ErrorResponse, got {typ!r}"
        assert "invalid oauth options" in _parse_error(body)
    finally:
        client.close()
    assert (
        'no validator module named "nosuch" is loaded'
        in oauth_two_validators.log_path.read_text()
    )


async def test_oauth_validator_required_when_ambiguous(oauth_two_validators):
    # With more than one module loaded there is no sensible default.
    await set_hba(oauth_two_validators, "host all all all oauth")

    client = RawClient(oauth_two_validators.host, oauth_two_validators.port)
    try:
        client.send_startup("oauthuser", "p0a")
        typ, body = client.read_message()
        assert typ == b"E", f"expected ErrorResponse, got {typ!r}"
        assert "invalid oauth options" in _parse_error(body)
    finally:
        client.close()
    assert (
        'the "validator" HBA option is required'
        in oauth_two_validators.log_path.read_text()
    )


# -------------------------------------------------------------------
# The Keycloak validator module (src/oauth-keycloak).
# -------------------------------------------------------------------

KEYCLOAK_DIR = TEST_DIR / ".." / "src" / "oauth-keycloak"
OIDC_DIR = TEST_DIR / ".." / "src" / "oauth-common"
OIDC_SOURCES = ("oidc_crypto.c", "oidc_http.c", "oidc_jwt.c", "oidc_util.c")


def build_keycloak_validator(tmp_path):
    """Build the Keycloak module, or skip if its dependencies are missing."""
    for pkg in ("libcurl", "jansson", "openssl"):
        if subprocess.run(["pkg-config", "--exists", pkg], check=False).returncode != 0:
            pytest.skip(f"{pkg} development files are not installed")

    so_path = tmp_path / "keycloak.so"
    cflags = subprocess.run(
        ["pkg-config", "--cflags", "--libs", "libcurl", "jansson", "openssl"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    sources = [str(KEYCLOAK_DIR / "keycloak.c")] + [
        str(OIDC_DIR / name) for name in OIDC_SOURCES
    ]
    subprocess.run(
        [
            "cc",
            "-shared",
            "-fPIC",
            "-pthread",
            f"-I{TEST_DIR / '..' / 'include'}",
            f"-I{OIDC_DIR}",
            "-o",
            str(so_path),
            *sources,
            *cflags,
        ],
        check=True,
    )
    return so_path


@pytest.fixture
async def keycloak_bouncer(bouncer, pg, tmp_path):
    """PgBouncer with the Keycloak module loaded and configured.

    No Keycloak is involved: the tests here cover the seam between PgBouncer
    and the module (loading, naming, its [oauth:keycloak] section), while the
    shared token handling is tested by src/oauth-common/oidc_test.c.
    """
    validator = build_keycloak_validator(tmp_path)

    pg.sql("drop role if exists oauthuser")
    pg.sql("create user oauthuser")
    with bouncer.auth_path.open("a") as f:
        f.write('"oauthuser" "unused"\n')

    bouncer.write_ini("auth_type = oauth")
    bouncer.write_ini(f"oauth_validator_libraries = {validator}")
    bouncer.write_ini("oauth_issuer = https://kc.example.test/realms/prod")
    bouncer.write_ini("[oauth:keycloak]")
    bouncer.write_ini("issuer = https://kc.example.test/realms/prod")
    bouncer.write_ini("audience = pgbouncer")
    await bouncer.restart()

    yield bouncer


async def test_keycloak_module_loads(keycloak_bouncer):
    log = keycloak_bouncer.log_path.read_text()
    # The module declares the name "keycloak" and finds its own section.
    assert 'loaded OAuth validator module "keycloak"' in log
    assert "(2 option(s))" in log
    assert "keycloak: configured for issuer https://kc.example.test/realms/prod" in log
    assert "mode=jwks" in log


async def test_keycloak_rejects_unknown_setting(keycloak_bouncer):
    await keycloak_bouncer.stop()
    keycloak_bouncer.write_ini("nosuchsetting = 1")

    output = await run_pgbouncer_expecting_failure(keycloak_bouncer)
    assert 'unrecognized setting "nosuchsetting" in [oauth:keycloak]' in output
    assert "failed to start" in output


async def test_keycloak_requires_issuer(bouncer, pg, tmp_path):
    validator = build_keycloak_validator(tmp_path)

    await bouncer.stop()
    bouncer.write_ini("auth_type = oauth")
    bouncer.write_ini(f"oauth_validator_libraries = {validator}")
    bouncer.write_ini("[oauth:keycloak]")
    bouncer.write_ini("audience = pgbouncer")

    output = await run_pgbouncer_expecting_failure(bouncer)
    assert '"issuer" is required in [oauth:keycloak]' in output


async def test_keycloak_introspect_needs_credentials(keycloak_bouncer):
    await keycloak_bouncer.stop()
    keycloak_bouncer.write_ini("mode = introspect")

    output = await run_pgbouncer_expecting_failure(keycloak_bouncer)
    assert "mode=introspect requires client_id and client_secret" in output


async def test_keycloak_rejects_garbage_token(keycloak_bouncer):
    # The JWKS endpoint does not exist, but a token that is not even a JWT is
    # turned down before the module ever tries to reach it.
    result = oauth_exchange(
        keycloak_bouncer, "oauthuser", "p0a", oauth_initial_response("not-a-jwt")
    )
    assert result["ok"] is False
    assert "OAuth authentication failed" in result["error"]
    assert "token is not a JWT" in keycloak_bouncer.log_path.read_text()
