#!/bin/bash
# End to end against a real Vaultwarden: starts the version compose.yaml pins in Docker, then e2e/vaultwarden.ts runs
# the README's first start through the API, Passwords' server and its pages' code against it, and the official
# Bitwarden CLI on the same accounts. Needs Docker and npx. Exits non-zero on failure.
set -u
cd "$(dirname "$0")/.."
IMAGE=$(sed -n 's/^ *image: \(vaultwarden\/server:.*\)$/\1/p' compose.yaml)
PORT=${E2E_VW_PORT:-18081}
cleanup() { docker rm -f passwords-e2e-vw >/dev/null 2>&1; }
cleanup
TLS=$(mktemp -d)
[ -n "${E2E_KEEP:-}" ] || trap 'cleanup; rm -rf "$TLS"' EXIT
# The Bitwarden apps and CLI only talk to https://, so Vaultwarden serves TLS with a certificate made for this run,
# which Node (the test and the CLI) trusts through NODE_EXTRA_CA_CERTS.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$TLS/key.pem" -out "$TLS/cert.pem" 2>/dev/null
chmod 644 "$TLS/key.pem" "$TLS/cert.pem"
# Sign-ups are on here only so the test can make its accounts; compose.yaml keeps them off. No SMTP, as in the README.
docker run -d --name passwords-e2e-vw -p "127.0.0.1:$PORT:80" -v "$TLS:/ssl:ro" -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' \
  -e DOMAIN="https://localhost:$PORT" -e SIGNUPS_ALLOWED=true -e INVITATIONS_ALLOWED=true \
  -e ORG_GROUPS_ENABLED=true -e ORG_EVENTS_ENABLED=true -e EVENTS_DAYS_RETAIN=400 \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 -e I_REALLY_WANT_VOLATILE_STORAGE=true "$IMAGE" >/dev/null
for _ in $(seq 1 60); do curl -sf --cacert "$TLS/cert.pem" "https://localhost:$PORT/alive" >/dev/null && break; sleep 0.5; done
curl -sf --cacert "$TLS/cert.pem" "https://localhost:$PORT/alive" >/dev/null || { echo "Vaultwarden did not start"; docker logs --tail 20 passwords-e2e-vw; exit 1; }
echo "# $IMAGE on port $PORT"
VW="https://localhost:$PORT" NODE_EXTRA_CA_CERTS="$TLS/cert.pem" node e2e/vaultwarden.ts
status=$?
[ $status -eq 0 ] || docker logs --tail 40 passwords-e2e-vw
exit $status
