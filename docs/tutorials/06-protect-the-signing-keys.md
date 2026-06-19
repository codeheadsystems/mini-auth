# Lab 06 — Protect the signing keys (capstone)

> **Tutorial (hands-on, guaranteed to succeed). The capstone.** Stage 6. ~20 minutes. Start
> **mini-kms**, create a key group, run an issuer with `--kms-*`, and **confirm only ciphertext
> touches disk** — yet tokens still issue and verify. This is the recursive integration: the family
> securing its own keys.
>
> **Concept:** [`envelope-encryption-and-kms.md`](../concepts/envelope-encryption-and-kms.md).
> **Diagram:** [`kms-wrap-on-save`](../diagrams/kms-wrap-on-save.md). Builds on
> [lab 03](03-machine-identity-end-to-end.md).

## The story

> "mini-idp signs tokens with a private key on disk. If someone steals `signing-keys.json`, they can
> forge any token. Wrap that key under mini-kms so the file holds only ciphertext."

## 1. Start mini-kms and create a key group

mini-kms reads its passphrase with no echo (or `MINIKMS_PASSPHRASE` with no TTY) and uses **two
tokens** — data plane and control plane:

```bash
./gradlew :services:mini-kms:server:installDist :services:mini-kms:client:installDist

export MINIKMS_PASSPHRASE="$(openssl rand -hex 24)"     # demo only; real use: a strong, stored passphrase
export MINIKMS_API_TOKEN="$(openssl rand -hex 32)"      # data plane (encrypt/decrypt)
export MINIKMS_ADMIN_TOKEN="$(openssl rand -hex 32)"    # control plane (create/rotate/destroy)

services/mini-kms/server/build/install/server/bin/server --tcp-port 9123 --keystore "$(mktemp -d)/keystore.json" &

KMS_CLIENT=services/mini-kms/client/build/install/client/bin
$KMS_CLIENT/client   --tcp 127.0.0.1:9123 health        # => ok
$KMS_CLIENT/kms-admin --tcp 127.0.0.1:9123 create-key --key signing-keys
# => created key group signing-keys; active version is now v1
```

The **API token** lets the data plane encrypt/decrypt; the **admin token** is required to `create-key`
or `rotate-key`. A leaked data-plane token can use keys but **cannot rotate or destroy** them
([envelope concept](../concepts/envelope-encryption-and-kms.md), "two planes").

## 2. Run mini-idp with its signing key wrapped

Point mini-idp at the KMS with `--kms-tcp` + `--kms-key-group`, and give it the **data-plane** token:

```bash
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"
export MINIIDP_KMS_API_TOKEN="$MINIKMS_API_TOKEN"        # mini-kms data-plane token

services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir "$(mktemp -d)" &

IDPDATA=$(mktemp -d)
services/mini-idp/server/build/install/server/bin/server --port 8455 --data-dir "$IDPDATA" \
  --directory-url http://127.0.0.1:8466 \
  --kms-tcp 127.0.0.1:9123 --kms-key-group signing-keys &
```

The banner now says it out loud:
```
signing keys: wrapped under mini-kms group 'signing-keys' at 127.0.0.1:9123
```
(Compare lab 03's `signing keys: local file (plaintext, 0600)`.)

## 3. Confirm only ciphertext is on disk

**Predict:** what's in `signing-keys.json` now? The private key? Look:

```bash
cat "$IDPDATA"/signing-keys.json
```
```json
{
  "activeKid" : "k_jJTsJjE2-ec",
  "keys" : [ {
    "kid" : "k_jJTsJjE2-ec",
    "privatePkcs8Base64" : "kms1:AgxzaWduaW5nLWtleXMAAAAAAAAAAQEBYtHcuUva9dleczY/mV5t0h0TeaiJ2hYmwCKFl1vfTuodV+fNnsBFdHrYOb/92MveFRIWuuVhWQdv3xzebg2IeMDonU58G+fwEc+Plw==",
    "publicSpkiBase64" : "MCowBQYDK2VwAyEAXexDPQ7+p4NWcj41TrTlNxE6kMB0Tm0mMIgNN1xMJWA=",
    "active" : true, "createdAt" : 1781834099, "retiredAt" : null
  } ]
}
```

The **private** field is `kms1:<ciphertext>` — an envelope wrapped under mini-kms, useless without
the KMS. The **public** key (`publicSpkiBase64`) is plaintext, as it should be (it's public — it's
what the JWKS publishes). Stealing this file no longer yields a forging key.

## 4. …and tokens still work

The wrapped key is unwrapped **in memory only**, at startup. So issuance and offline verification are
unchanged:

```bash
DIR="http://127.0.0.1:8466"; IDP="http://127.0.0.1:8455"
REG=$(curl -fsS -X POST "$DIR/admin/service-accounts" -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"displayName":"agent","admin":false,"grants":[{"action":"ENCRYPT","resource":"grafana"}]}')
CID=$(echo "$REG"|python3 -c 'import sys,json;print(json.load(sys.stdin)["account"]["id"])')
SEC=$(echo "$REG"|python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')

AT=$(curl -fsS -X POST "$IDP/oauth/token" -d "grant_type=client_credentials&client_id=$CID&client_secret=$SEC" \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

python3 - "$AT" "$(curl -fsS $IDP/.well-known/jwks.json)" <<'PY'
import sys,base64,json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
def b64u(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
tok,jwks=sys.argv[1],json.loads(sys.argv[2]); h,p,sig=tok.split(".")
jwk=next(k for k in jwks["keys"] if k["kid"]==json.loads(b64u(h))["kid"])
Ed25519PublicKey.from_public_bytes(b64u(jwk["x"])).verify(b64u(sig),(h+"."+p).encode())
print("SIGNATURE VALID ✓  (key unwrapped from mini-kms in memory, signed, verifies)")
PY
```
```
SIGNATURE VALID ✓  (key unwrapped from mini-kms in memory, signed, verifies)
```

The token verifies against the same JWKS as lab 02 — the wrapping is **transparent** to the token
plane. `kid` is bound into the ciphertext as AAD, so a wrapped blob can't be swapped between records.

```bash
kill %1 %2 %3 2>/dev/null   # stop directory, idp, kms
```

## What you just learned

- **The family secures its own keys.** The token-signing private key is envelope-wrapped under
  mini-kms; the on-disk file is `kms1:<ciphertext>`, unwrapped only in memory.
- **It's transparent and reused.** `SigningKeyService` doesn't know; the same `KmsSigningKeyStore`
  decorator protects mini-idp, mini-oidc, *and* mini-ca's CA key.
- **`kid`-as-AAD** binds each wrapped key to its identity (encryption context).
- **Two planes, two tokens:** data-plane can use keys; only control-plane can rotate/destroy.

## Try it yourself (optional)

- **Workload identity variant:** run **mini-ca** with `--kms-tcp`/`--kms-key-group` and confirm its
  `ca-key.json` is also a `kms1:` envelope — the same integration protects a CA key (capstone variant;
  see `services/mini-ca/README.md`).
- **Rotate the KEK:** `kms-admin rotate-key --key signing-keys`, then re-`rewrap` the issuer's keys —
  decrypt-under-old / re-encrypt-under-new happens *inside* mini-kms; the plaintext never leaves it.
  See [`howto/rotate-a-kms-kek.md`](../howto/rotate-a-kms-kek.md).
- **Crypto-shredding:** `destroy-version` is irreversible — anything wrapped under it is gone for good.

This is the end of the stage ladder. For operating the whole family, see
[`howto/run-the-whole-family.md`](../howto/run-the-whole-family.md). For the transferable security
reflexes, [`concepts/secure-design-invariants.md`](../concepts/secure-design-invariants.md).
