# notes-app

A note-keeping app for web, Android, Linux, Windows and a small embedded device,
with end-to-end encrypted sync. The server never sees note contents or keys.

**Status:** the sync server, the shared core and the web app exist. The
Android, desktop and embedded clients do not yet.

| | |
|---|---|
| [`design/`](design) | Architecture, protocol and interface design (PlantUML, OpenAPI) |
| [`common/core/`](common/core) | The shared core (Rust, `no_std`): encryption, note model, sync. Every client uses it. |
| [`client/web/`](client/web) | The web app (React, Vite, TypeScript; the core as WebAssembly) |
| [`server/`](server) | `notes-syncd`, the sync server (Rust). Also serves the web app. |
| [`deploy/`](deploy) | Kubernetes manifests and scripts for the deployment at notes.magical.rocks |

## How the parts fit

The core does everything that must be the same on every platform: keys,
encryption, the note model, conflict resolution and sync. It reaches the
outside world only through six small interfaces (the HAL): HTTP, file storage,
secret storage, clock, network state and randomness. A client is a HAL
implementation plus a user interface.

In the web app the HAL is a set of TypeScript classes
([`client/web/src/hal`](client/web/src/hal)). The interface follows MVVM: all
state and behaviour live in view-model classes
([`client/web/src/viewmodels`](client/web/src/viewmodels)), and the React
function components in [`client/web/src/views`](client/web/src/views) only
render that state and forward input.

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
- `tests/core_client.rs` runs the shared core against the server.

## Web app

Needs Rust (the toolchain in `rust-toolchain.toml`), Node.js and
`cargo install wasm-bindgen-cli --version 0.2.130 --locked`.

```sh
cd client/web
npm ci
npm run build        # WebAssembly core, type check, bundle -> dist/
npm run dev          # development server; expects notes-syncd on 127.0.0.1:8443
```

Set `static_dir` in the server's config to the `dist` folder and the server
serves the app at `/app/`, under a Content Security Policy that allows nothing
but the app's own files. The container image (`docker build -t notes-syncd .`
in this folder) has the app built in.

## Security

Please report vulnerabilities privately through GitHub's
"Report a vulnerability" on the Security tab, not as a public issue.
