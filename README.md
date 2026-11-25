# notes-app

A note-keeping app for web, Android, Linux, Windows and a small embedded device,
with end-to-end encrypted sync. The server never sees note contents or keys.

**Status:** the design and the sync server exist; the clients do not yet.

| | |
|---|---|
| [`design/`](design) | Architecture, protocol and interface design (PlantUML, OpenAPI) |
| [`server/`](server) | `notes-syncd`, the sync server (Rust) |
| [`deploy/`](deploy) | Kubernetes manifests and scripts for the deployment at notes.magical.rocks |

## Server

```sh
cd server
cp config.example.toml config.toml   # set an invite code
cargo run -- config.toml
cargo test
```

- REST + JSON over HTTPS, TLS 1.3 only. The API is described in
  [`design/interface/openapi.yaml`](design/interface/openapi.yaml).
- SQLite by default, Postgres by setting `database_url`.
- New accounts by invite code, by OpenID Connect login (for example Keycloak),
  or either.
- `tests/keycloak_e2e.py` checks the OIDC login against a real Keycloak.

## Security

Please report vulnerabilities privately through GitHub's
"Report a vulnerability" on the Security tab, not as a public issue.
