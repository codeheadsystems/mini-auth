#!/bin/sh
# Default the issuer to the loopback URL on the configured port (see the Dockerfile), then run the
# server. Secrets (MINIIDP_ADMIN_TOKEN, MINIIDP_SERVICE_ACCOUNTS) stay in the environment; nothing
# here prints them.
set -eu
: "${MINIIDP_ISSUER:=http://localhost:${MINIIDP_PORT}}"
export MINIIDP_ISSUER
exec /opt/mini-idp/bin/server "$@"
