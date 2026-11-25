#!/usr/bin/env bash
# Prints a kubeconfig for the ci-deployer service account (see
# k8s/ci-access.yaml). Pipe it straight into the GitHub secret so that it
# never touches the disk:
#
#     deploy/ci-kubeconfig.sh https://<api-server>:6443 | gh secret set KUBECONFIG -R SetZero/notes-app
#
# The address must be reachable from the GitHub runners. Without an argument
# the address of the current kubectl context is used.
set -euo pipefail
NS=notes
server=${1:-$(kubectl config view --minify -o jsonpath="{.clusters[0].cluster.server}")}
token=$(kubectl -n "$NS" get secret ci-deployer-token -o jsonpath="{.data.token}" | base64 -d)
ca=$(kubectl -n "$NS" get secret ci-deployer-token -o jsonpath="{.data.ca\.crt}")
cat <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
  - name: cluster
    cluster:
      server: $server
      certificate-authority-data: $ca
users:
  - name: ci-deployer
    user:
      token: $token
contexts:
  - name: ci
    context:
      cluster: cluster
      user: ci-deployer
      namespace: $NS
current-context: ci
KUBECONFIG
