# Lab 03 — Machine identity, end to end

> **Tutorial (hands-on, guaranteed to succeed).** Stage 3. ~15 minutes. The first lab in the
> persistent scenario: a **machine** (`grafana-agent`) gets a token and is authorized. You compose
> two services — directory + issuer — and, importantly, **watch it fail** when the directory is gone.
>
> **Concepts:** [`oauth-and-oidc-flows.md`](../concepts/oauth-and-oidc-flows.md) (client-credentials)
> + [`what-a-token-is.md`](../concepts/what-a-token-is.md). **Diagram:**
> [`client-credentials`](../diagrams/client-credentials.md). Assumes you did
> [lab 02](02-build-and-verify-a-token-by-hand.md).

## The story

> "A Grafana agent in my homelab needs to call a protected API. It's a machine — it can hold a
> secret. Give it an identity and a short-lived token."

Two services collaborate: **mini-directory** owns the service account (and verifies its secret);
**mini-idp** issues the token. Lab 02 already wired these — this lab frames the *composition* and
its failure modes.

## 1. Bring up the two services

```bash
./gradlew :services:mini-directory:installDist :services:mini-idp:server:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"   # idp authenticates to the directory's admin API

services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir "$(mktemp -d)" &
services/mini-idp/server/build/install/server/bin/server --port 8455 --data-dir "$(mktemp -d)" \
  --directory-url http://127.0.0.1:8466 &

DIR="http://127.0.0.1:8466"; IDP="http://127.0.0.1:8455"
```

The mini-idp banner states the wiring: `service accounts: read from mini-directory at
http://127.0.0.1:8466`. **mini-idp stores no clients** — it asks the directory at every token
request.

## 2. Create the agent and get its token

```bash
REG=$(curl -fsS -X POST "$DIR/admin/service-accounts" \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"displayName":"grafana-agent","admin":false,"grants":[{"action":"ENCRYPT","resource":"grafana"}]}')
CID=$(echo "$REG"|python3 -c 'import sys,json;print(json.load(sys.stdin)["account"]["id"])')
SEC=$(echo "$REG"|python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')

curl -fsS -X POST "$IDP/oauth/token" -d "grant_type=client_credentials&client_id=$CID&client_secret=$SEC"
```
```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300, "scope": "grafana:ENCRYPT" }
```

The token's `grants` claim is the directory grant, resolved and signed in. (Decode it as in lab 02 to
confirm.) That's the **happy path**: identity in the directory → secret verified → grants resolved →
signed token.

## 3. Predict the failure modes — then cause them

A real homelab fails. Predict each outcome **before** running it, then check.

**(a) Wrong secret.** Predict the status and body:

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST "$IDP/oauth/token" \
  -d "grant_type=client_credentials&client_id=$CID&client_secret=WRONG"
# {"error":"invalid_client","error_description":"client authentication failed"}   HTTP 401
```

**(b) Unknown client.** Same generic error — **no oracle** tells you the client doesn't exist:

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST "$IDP/oauth/token" \
  -d "grant_type=client_credentials&client_id=svc_ghost&client_secret=WRONG"
# byte-identical invalid_client / 401
```

**(c) The directory is down.** This is the one operators hit. Kill mini-directory, then ask for a
token. **Predict:** does mini-idp 500? Leak "directory unreachable"? Something else?

```bash
kill %1     # stop mini-directory (job 1)
curl -s -w "\nHTTP %{http_code}\n" -X POST "$IDP/oauth/token" \
  -d "grant_type=client_credentials&client_id=$CID&client_secret=$SEC"
```
```json
{ "error": "invalid_client", "error_description": "client authentication failed" }
HTTP 401
```

It collapses to the **same** `invalid_client`. The no-oracle discipline is so thorough that even an
*infrastructure outage* doesn't leak — a caller can't distinguish "directory down" from "bad secret."
(Operationally you'd watch logs/health for that; the *token endpoint* stays silent.)

**(d) …but the JWKS still serves.** Publishing public keys needs no directory:

```bash
curl -s -o /dev/null -w "jwks HTTP %{http_code}\n" "$IDP/.well-known/jwks.json"   # => 200
```

So *already-issued* tokens keep verifying offline even while the issuer can't mint new ones — the
verify path and the issue path are decoupled (that's the whole point of offline verification).

```bash
kill %2 2>/dev/null   # stop mini-idp
```

## What you just learned

- **Machine identity is a composition:** the directory authenticates + resolves; the issuer signs. No
  one service does both.
- **The no-oracle property is end-to-end** — wrong secret, unknown client, and *directory down* are
  indistinguishable to a caller.
- **Issue and verify are decoupled:** JWKS (and thus offline verification of old tokens) survives a
  directory outage.

## Try it yourself (optional)

- Give the agent a *role* in the directory instead of a direct grant (lab 01 style), re-issue, and
  confirm the resolved `grants` claim is identical.
- Set `--token-ttl-seconds 10`, issue a token, wait, and re-run an offline verify (lab 02's script
  with a time check) — signature still valid, claims expired.

Next: stage 4, [`04-human-sso-end-to-end.md`](04-human-sso-end-to-end.md) — the *human* half, with
passkeys and a browser session.
