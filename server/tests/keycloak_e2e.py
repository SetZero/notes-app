"""End-to-end check of OIDC enrollment against a real Keycloak.

Not part of `cargo test`: it needs a running Keycloak (dev mode is enough) and
the built server binary. It creates a realm, a public client and a user in
Keycloak, starts notes-syncd configured for that realm, and then signs in with
the authorization code flow (PKCE + nonce) the way a client app would.

    python tests/keycloak_e2e.py http://127.0.0.1:8080 admin <admin-password>

Only for local test instances: it deletes and recreates the realm "notes-e2e".
"""
import base64, hashlib, html, json, os, re, secrets, subprocess
from http.cookiejar import CookieJar
import sys, tempfile, time, urllib.error, urllib.parse, urllib.request

KC, ADMIN, ADMIN_PW = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
REALM, CLIENT, REDIRECT = "notes-e2e", "notes-app", "http://127.0.0.1:58099/callback"
SERVER = "http://127.0.0.1:58443"
USER, USER_PW = "alice", secrets.token_urlsafe(12)
HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(HERE, "..", "target", "debug", "notes-syncd" + (".exe" if os.name == "nt" else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http(method, url, body=None, form=None, token=None, opener=None):
    headers, data = {}, None
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = (opener or urllib.request.build_opener(NoRedirect)).open(req, timeout=30)
    except urllib.error.HTTPError as e:
        resp = e
    if resp.status == 429 and url.startswith(SERVER):
        # The server allows 10 enrollment attempts per minute and address.
        time.sleep(int(resp.headers.get("Retry-After", "5")) + 1)
        return http(method, url, body, form, token, opener)
    raw = resp.read()
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return resp.status, resp.headers, parsed


def setup_keycloak():
    _, _, tok = http("POST", f"{KC}/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": ADMIN, "password": ADMIN_PW})
    admin = tok["access_token"]
    http("DELETE", f"{KC}/admin/realms/{REALM}", token=admin)
    status, _, body = http("POST", f"{KC}/admin/realms", token=admin, body={
        "realm": REALM, "enabled": True,
        "clients": [{
            "clientId": CLIENT, "publicClient": True, "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False, "redirectUris": [REDIRECT],
            "attributes": {"pkce.code.challenge.method": "S256"},
        }, {
            "clientId": "other-app", "publicClient": True, "standardFlowEnabled": True,
            "redirectUris": [REDIRECT],
        }],
        "users": [{
            "username": USER, "enabled": True, "email": "alice@example.test", "emailVerified": True,
            "firstName": "Alice", "lastName": "Test",
            "credentials": [{"type": "password", "value": USER_PW, "temporary": False}],
        }],
    })
    assert status == 201, (status, body)


def login(nonce, client=CLIENT):
    """Authorization code flow with PKCE; returns the token response."""
    jar = CookieJar()
    browser = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar))
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
        "client_id": client, "redirect_uri": REDIRECT, "response_type": "code", "scope": "openid",
        "nonce": nonce, "state": secrets.token_urlsafe(8),
        "code_challenge": challenge, "code_challenge_method": "S256"})
    status, _, page = http("GET", f"{KC}/realms/{REALM}/protocol/openid-connect/auth?{query}", opener=browser)
    assert status == 200, (status, page)
    action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page).group(1))
    # Keycloak marks its cookies Secure; a browser still sends them to a
    # loopback http address, Python's cookie jar does not.
    browser.addheaders = [("Cookie", "; ".join(f"{c.name}={c.value}" for c in jar))]
    status, headers, page = http("POST", action, form={"username": USER, "password": USER_PW}, opener=browser)
    assert status == 302, (status, str(page)[:400])
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)["code"][0]
    status, _, tokens = http("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", form={
        "grant_type": "authorization_code", "client_id": client, "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert status == 200, (status, tokens)
    return tokens


def server_nonce():
    status, _, body = http("POST", f"{SERVER}/v1/auth/oidc/nonce", body={"provider": "keycloak"})
    assert status == 200, (status, body)
    return body["nonce"]


def create_account(id_token):
    return http("POST", f"{SERVER}/v1/accounts", body={
        "device_name": "e2e", "recovery_verifier": base64.b64encode(b"\x09" * 32).decode(),
        "oidc": {"provider": "keycloak", "id_token": id_token}})[::2]


RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"   -> {detail}"))


def main():
    setup_keycloak()
    data_dir = tempfile.mkdtemp(prefix="notes-e2e-")
    config = os.path.join(data_dir, "config.toml")
    with open(config, "w") as f:
        f.write(f"""
[server]
listen = "127.0.0.1:58443"
data_dir = '{data_dir}'

[enrollment]
mode = "oidc"

[[oidc]]
id = "keycloak"
issuer = "{KC}/realms/{REALM}"
client_id = "{CLIENT}"
allow_insecure_http = true
""")
    log = open(os.path.join(data_dir, "server.log"), "w")
    server = subprocess.Popen([BINARY, config], stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if http("GET", f"{SERVER}/healthz")[0] == 200:
                    break
            except OSError:
                time.sleep(0.2)
        status, _, meta = http("GET", f"{SERVER}/v1/meta")
        check("meta lists the provider", status == 200 and meta["auth"]["oidc"][0]["id"] == "keycloak", meta)

        tokens = login(server_nonce())
        status, body = create_account(tokens["id_token"])
        check("login creates an account", status == 201, (status, body))
        account_id, device_token = (body or {}).get("account_id"), (body or {}).get("token")

        status, body = http("GET", f"{SERVER}/v1/devices", token=device_token)[::2]
        check("issued device token works", status == 200, (status, body))

        status, body = create_account(tokens["id_token"])
        check("same ID token cannot be used twice", status == 403, (status, body))

        status, body = create_account(tokens["access_token"])
        check("access token is not accepted as ID token", status == 403, (status, body))

        status, body = create_account(login(secrets.token_urlsafe(16))["id_token"])
        check("nonce not issued by the server is refused", status == 403, (status, body))

        status, body = create_account(login(server_nonce(), client="other-app")["id_token"])
        check("token for another client is refused", status == 403, (status, body))

        parts = login(server_nonce())["id_token"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        payload["sub"] = "someone-else"
        parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        status, body = create_account(".".join(parts))
        check("tampered token is refused", status == 403, (status, body))

        status, body = create_account(login(server_nonce())["id_token"])
        check("second account for the same identity is refused",
              status == 409 and body.get("account_id") == account_id, (status, body))

        recover = f"{SERVER}/v1/accounts/{account_id}/recover"
        verifier = base64.b64encode(b"\x09" * 32).decode()
        status, body = http("POST", recover, body={"device_name": "new", "recovery_verifier": verifier})[::2]
        check("recovery without login is refused", status in (401, 403), (status, body))
        status, body = http("POST", recover, body={
            "device_name": "new", "recovery_verifier": verifier,
            "oidc": {"provider": "keycloak", "id_token": login(server_nonce())["id_token"]}})[::2]
        check("recovery with phrase and login works", status in (200, 201), (status, body))
    finally:
        server.terminate()
        server.wait(timeout=10)
        log.close()
        if not all(RESULTS):
            print("--- server log ---")
            print(open(os.path.join(data_dir, "server.log")).read()[-3000:])
    print(f"{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if RESULTS and all(RESULTS) else 1)


main()
