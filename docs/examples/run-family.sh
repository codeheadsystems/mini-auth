#!/usr/bin/env bash
#
# run-family.sh — bring up the mini-auth family in dependency order, for the
# teaching docs (see docs/howto/run-the-whole-family.md). Educational/local only:
# loopback binds, demo secrets, plaintext data dirs under a temp root.
#
# Order:  mini-kms (optional) -> mini-directory -> mini-idp / mini-oidc -> mini-gateway
#         -> mini-ca -> mini-console (the admin console over everything above)
#
# Usage:   docs/examples/run-family.sh [--with-kms]
#          Ctrl-C to tear everything down.
#
set -euo pipefail

WITH_KMS=0
[ "${1:-}" = "--with-kms" ] && WITH_KMS=1

# Resolve repo root from this script's location (docs/examples/ -> ../../).
# CDPATH= guards against a shell-configured CDPATH making `cd` echo its target.
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "$ROOT"

RUN_DIR="$(mktemp -d)"
PIDS=()
cleanup() { echo; echo "shutting down…"; for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup INT TERM EXIT

wait_health() {  # $1 = url, $2 = name
  for _ in $(seq 1 60); do
    curl -fsS "$1" >/dev/null 2>&1 && { echo "  $2 up"; return 0; }
    sleep 0.3
  done
  echo "  $2 FAILED to start; see $RUN_DIR/$2.log" >&2; exit 1
}

echo "== building launchers =="
TARGETS=":services:mini-directory:installDist :services:mini-idp:server:installDist \
         :services:mini-oidc:installDist :services:mini-gateway:installDist \
         :services:mini-ca:installDist :services:mini-console:installDist"
[ "$WITH_KMS" = 1 ] && TARGETS="$TARGETS :services:mini-kms:server:installDist :services:mini-kms:client:installDist"
# shellcheck disable=SC2086
./gradlew $TARGETS -q

# ---- shared demo secrets (env/file, never argv) ----------------------------
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"     # idp  -> directory admin API
export MINIOIDC_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIOIDC_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"    # oidc -> directory admin API
export MINICA_ADMIN_TOKEN="$(openssl rand -hex 32)"
# mini-console holds its own login token plus a CONSOLE-SCOPED copy of each downstream admin
# token (MINICONSOLE_* names, never the downstream var) — the one new secret concentration.
export MINICONSOLE_ADMIN_TOKEN="$(openssl rand -hex 32)"  # the console login token

echo "MiniConsole admin token: $MINICONSOLE_ADMIN_TOKEN"

export MINICONSOLE_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"
export MINICONSOLE_IDP_TOKEN="$MINIIDP_ADMIN_TOKEN"
export MINICONSOLE_OIDC_TOKEN="$MINIOIDC_ADMIN_TOKEN"
export MINICONSOLE_CA_TOKEN="$MINICA_ADMIN_TOKEN"

KMS_ARGS=()
CA_KMS_ARGS=()
CONSOLE_KMS_ARGS=()
if [ "$WITH_KMS" = 1 ]; then
  echo "== mini-kms (key wrapping) =="
  export MINIKMS_PASSPHRASE="$(openssl rand -hex 24)"
  export MINIKMS_API_TOKEN="$(openssl rand -hex 32)"
  export MINIKMS_ADMIN_TOKEN="$(openssl rand -hex 32)"
  services/mini-kms/server/build/install/server/bin/server \
    --tcp-port 9123 --keystore "$RUN_DIR/keystore.json" > "$RUN_DIR/mini-kms.log" 2>&1 &
  PIDS+=($!)
  CLI=services/mini-kms/client/build/install/client/bin
  for _ in $(seq 1 60); do "$CLI/client" --tcp 127.0.0.1:9123 health >/dev/null 2>&1 && break; sleep 0.3; done
  echo "  mini-kms up"
  "$CLI/kms-admin" --tcp 127.0.0.1:9123 create-key --key signing-keys >/dev/null
  "$CLI/kms-admin" --tcp 127.0.0.1:9123 create-key --key ca-key >/dev/null
  export MINIIDP_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
  export MINICA_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
  # The console's Keys page drives the mini-kms control plane, so it holds BOTH kms tokens.
  export MINICONSOLE_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
  export MINICONSOLE_KMS_ADMIN_TOKEN="$MINIKMS_ADMIN_TOKEN"
  KMS_ARGS=(--kms-tcp 127.0.0.1:9123 --kms-key-group signing-keys)
  CA_KMS_ARGS=(--kms-tcp 127.0.0.1:9123 --kms-key-group ca-key)
  CONSOLE_KMS_ARGS=(--kms-tcp 127.0.0.1:9123)
fi

echo "== mini-directory (identity source of truth) =="
services/mini-directory/build/install/mini-directory/bin/mini-directory \
  --port 8466 --data-dir "$RUN_DIR/directory" > "$RUN_DIR/mini-directory.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8466/health mini-directory

echo "== mini-idp (machine tokens) =="
services/mini-idp/server/build/install/server/bin/server \
  --port 8455 --data-dir "$RUN_DIR/idp" --directory-url http://127.0.0.1:8466 \
  "${KMS_ARGS[@]}" > "$RUN_DIR/mini-idp.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8455/health mini-idp

echo "== mini-oidc (human SSO) =="
services/mini-oidc/build/install/mini-oidc/bin/mini-oidc \
  --port 8477 --issuer http://127.0.0.1:8477 --rp-id 127.0.0.1 --rp-origin http://127.0.0.1:8477 \
  --directory-url http://127.0.0.1:8466 > "$RUN_DIR/mini-oidc.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8477/health mini-oidc

echo "== mini-gateway (forward-auth) =="
echo '{}' > "$RUN_DIR/sessions.json"
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway \
  --port 8488 --sessions-file "$RUN_DIR/sessions.json" \
  --routes-file services/mini-gateway/examples/routes.json \
  --login-url "http://127.0.0.1:8477/authorize" \
  --jwks-url http://127.0.0.1:8477/jwks.json \
  --issuer http://127.0.0.1:8477 --audience http://127.0.0.1:8477/userinfo \
  > "$RUN_DIR/mini-gateway.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8488/health mini-gateway

echo "== mini-ca (internal certificate authority) =="
services/mini-ca/build/install/mini-ca/bin/mini-ca \
  --port 8499 --data-dir "$RUN_DIR/ca" \
  "${CA_KMS_ARGS[@]}" > "$RUN_DIR/mini-ca.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8499/health mini-ca

echo "== mini-console (admin console over the family) =="
services/mini-console/build/install/mini-console/bin/mini-console \
  --port 8500 --data-dir "$RUN_DIR/console" \
  --directory-url http://127.0.0.1:8466 \
  --idp-url       http://127.0.0.1:8455 \
  --oidc-url      http://127.0.0.1:8477 \
  --ca-url        http://127.0.0.1:8499 \
  --gateway-url   http://127.0.0.1:8488 \
  "${CONSOLE_KMS_ARGS[@]}" > "$RUN_DIR/mini-console.log" 2>&1 &
PIDS+=($!)
wait_health http://127.0.0.1:8500/health mini-console

cat <<EOF

== family is up (loopback only) ==
  mini-directory  http://127.0.0.1:8466/docs   (admin: \$MINIDIR_ADMIN_TOKEN)
  mini-idp        http://127.0.0.1:8455/docs   (admin: \$MINIIDP_ADMIN_TOKEN)
  mini-oidc       http://127.0.0.1:8477/docs   (admin: \$MINIOIDC_ADMIN_TOKEN)
  mini-gateway    http://127.0.0.1:8488/verify
  mini-ca         http://127.0.0.1:8499/docs   (admin: \$MINICA_ADMIN_TOKEN)
  mini-console    http://127.0.0.1:8500/login  (login: \$MINICONSOLE_ADMIN_TOKEN; API docs: /docs)
$( [ "$WITH_KMS" = 1 ] && echo "  mini-kms        tcp://127.0.0.1:9123  (idp + ca keys wrapped)" )

  logs + data:    $RUN_DIR
  Ctrl-C to stop everything.
EOF

# Hold open until interrupted.
wait
