# Deploying notes-syncd to magical.rocks

The server runs in the cluster as one pod in its own namespace `notes`, behind
Traefik at **https://notes.magical.rocks**.

| Part | Where |
|---|---|
| Image | `ghcr.io/setzero/notes-syncd` (public), built by CI for amd64 and arm64 |
| Manifests | [`k8s/`](k8s) (apply with `kubectl apply -k`) |
| State | SQLite database and encrypted attachments on the `notes-syncd-data` volume |
| TLS | Traefik, certificate from `letsencrypt-production`, TLS 1.3 only |
| New accounts | invite code in the `notes-syncd-invite` secret; Keycloak optional |

## One-time setup

1. **DNS**: add a record `notes.magical.rocks` pointing where `magical.rocks`
   points. Without it cert-manager cannot get a certificate.
2. **Install**, on a machine where `kubectl` has admin access to the cluster:

   ```sh
   git clone https://github.com/SetZero/notes-app && cd notes-app
   deploy/install.sh
   ```

   This creates a random invite code (once), applies the manifests and waits
   for the pod.

## Day to day

- **New server version**: push to `main`. CI tests (SQLite and Postgres),
  builds and publishes the image; the `image-updater` job in the cluster rolls
  it out within five minutes. The API server is not reachable from the
  internet, so nothing is pushed in and GitHub holds no cluster credentials.
- **Did it roll out?** `kubectl -n notes get cronjob,job` and
  `kubectl -n notes logs job/<newest image-updater job>`
- **Stop automatic rollouts**:
  `kubectl -n notes patch cronjob image-updater -p '{"spec":{"suspend":true}}'`
- **Changed manifests or config**: run `deploy/install.sh` again. It keeps the
  image that is currently deployed.
- **Invite code**:
  `kubectl -n notes get secret notes-syncd-invite -o jsonpath={.data.invite-code} | base64 -d`
- **Sign-in with Keycloak**: create a public client (standard flow, PKCE) in a
  realm on keycloak.magical.rocks, fill in the `[[oidc]]` block in
  [`k8s/config.yaml`](k8s/config.yaml), set `mode = "either"` and run
  `deploy/install.sh`.
- **Logs**: `kubectl -n notes logs deploy/notes-syncd`

## What to check after the first install

- `trusted_proxies` in `k8s/config.yaml` assumes the k3s default pod network
  `10.42.0.0/16`. If the logs show every client with the same address, rate
  limits are shared by everyone; correct the range.
- The data volume is `local-path`, so it lives on one node and is not backed
  up by anything in this repository.
