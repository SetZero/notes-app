#!/usr/bin/env bash
# First installation, and later changes to the manifests. Run it where kubectl
# has admin access to the cluster:
#
#     deploy/install.sh
#
# It creates the invite code once (never overwrites it), applies everything in
# deploy/k8s and waits for the server to be up. Rolling out new versions of
# the server happens by itself (k8s/updater.yaml) and does not need this script.
set -euo pipefail
cd "$(dirname "$0")"
NS=notes

kubectl apply -f k8s/namespace.yaml

if ! kubectl -n "$NS" get secret notes-syncd-invite >/dev/null 2>&1; then
  # 192 bits from the kernel, never printed and never written to disk here.
  head -c 24 /dev/urandom | base64 | tr "+/" "-_" | tr -d "\n" \
    | kubectl -n "$NS" create secret generic notes-syncd-invite --from-file=invite-code=/dev/stdin
  echo "Created the invite code. Read it with:"
  echo "  kubectl -n $NS get secret notes-syncd-invite -o jsonpath={.data.invite-code} | base64 -d"
fi

# Keep the image that is deployed now; the manifest only names :latest.
current=$(kubectl -n "$NS" get deployment notes-syncd \
  -o jsonpath="{.spec.template.spec.containers[0].image}" 2>/dev/null || true)

kubectl apply -k k8s

if [ -n "$current" ]; then
  kubectl -n "$NS" set image deployment/notes-syncd notes-syncd="$current"
fi
# A changed ConfigMap is only read at start.
kubectl -n "$NS" rollout restart deployment/notes-syncd
kubectl -n "$NS" rollout status deployment/notes-syncd --timeout=180s
kubectl -n "$NS" get certificate notes-tls-secret
