# mini-ca

A small **internal certificate authority** for the homelab. It issues and renews **short-lived**
X.509 leaf certificates — for mTLS between the minis and for homelab services — from PKCS#10 CSRs,
keeps an issuance log and a revocation list, and protects its own CA private key by **wrapping it
under [mini-kms](../mini-kms)** (the same KMS-backed key store the token plane uses).

It is **educational, but homelab-functional**: real EC P-256 / ECDSA crypto via the JDK + Bouncy
Castle, loopback-bound, admin-token guarded, with no secrets in logs — but deliberately **not a full
PKI** (see non-goals).

## Scope

- One **self-signed root** (EC P-256, `SHA256withECDSA`), long-lived; the leaves are the short-lived
  ones.
- **Issue** a leaf from a CSR (`POST /issue`): the requester keeps its own private key and submits a
  PKCS#10 CSR; the CA verifies the CSR's proof-of-possession and signs an mTLS leaf (`CA:false`,
  `digitalSignature + keyEncipherment`, EKU `clientAuth + serverAuth`, requested SANs, a random
  serial, a clamped short TTL).
- **Renew** (`POST /renew`): issue a fresh leaf and, given the prior serial, revoke it (rotation).
- **Revoke** (`POST /revoke`) + a pollable **revocation list** (`GET /revocations`).
- **Issuance log** (`GET /log`) and the public **trust anchor** (`GET /ca`).
- The **CA private key is wrapped under mini-kms** when configured (`--kms-*`), else stored
  plaintext-`0600` so the educational path runs without mini-kms.

## Non-goals (what this is NOT)

This is the teaching version of a CA, not a production PKI. Deliberately out of scope:

- **No intermediates / chain depth** — a single self-signed root signs leaves directly (`pathLen 0`).
- **No signed DER CRL and no OCSP** — revocation is a **JSON list of serials**; a real verifier
  would consume a signed CRL or OCSP. (The list is the seam where those would plug in.)
- **No policy / name constraints / templated profiles** — every leaf gets the same mTLS extension set.
- **No automatic renewal / ACME** — clients re-submit a CSR; there is no challenge protocol.
- **No HSM, no key ceremony, no offline root** — the root is online; its key is protected only by
  mini-kms wrapping (or `0600`).
- **Not audited.** Homelab trust only.

## Run it

The bootstrap admin token comes from an env var or a file — **never a CLI arg, never logged**.

```bash
export MINICA_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-ca:installDist
services/mini-ca/build/install/mini-ca/bin/mini-ca --port 8499 --data-dir ~/.mini-ca
```

```bash
B=http://127.0.0.1:8499; H="Authorization: Bearer $MINICA_ADMIN_TOKEN"
# Make a key + CSR (the private key stays here, with the requester):
openssl ecparam -name prime256v1 -genkey -noout -out svc.key
openssl req -new -key svc.key -subj "/CN=billing.svc" -out svc.csr
# Issue (CSR as a JSON string):
curl -s -XPOST $B/issue -H "$H" -H 'Content-Type: application/json' \
  -d "{\"csr\":$(jq -Rs . < svc.csr),\"ttlSeconds\":3600,\"sans\":[\"billing.svc\"]}"
#   => { "serial":"…", "certificate":"-----BEGIN CERTIFICATE-----…", "caCertificate":"…", "notAfter":… }
curl -s $B/ca -o ca.pem            # the trust anchor (public)
curl -s $B/revocations             # the revocation list (public)
```

## API

`/ca`, `/revocations`, `/health`, and the docs are **public** (a verifier needs the anchor + CRL);
issuance/renewal/revocation/log require `Authorization: Bearer <admin token>`. Full contract:
`/openapi.yaml`, `/openapi.json`, Swagger UI at `/docs`.

| Method + path | Purpose |
| --- | --- |
| `GET /ca` | The CA root certificate (PEM) — the trust anchor. |
| `GET /revocations` | The revocation list (JSON). |
| `POST /issue` | Issue a leaf from a CSR → `{serial, certificate, caCertificate, notAfter}`. |
| `POST /renew` | Issue a fresh leaf; revoke the prior serial if given. |
| `POST /revoke` | Revoke a certificate by serial (idempotent). |
| `GET /log` | The issuance log. |

## Protecting the CA key under mini-kms

The CA private key is persisted as a one-record mini-token `SigningKeys` document through the same
`KmsSigningKeyStore` the token plane uses. With mini-kms configured it is envelope-encrypted at rest;
the key is unwrapped into memory once at bootstrap. (See `docs/DIRECTION.md` for the bootstrap
ordering and failure modes — they are the same as for the token signing keys.)

```bash
# Create the CA's key group once (control plane), then run mini-ca pointed at mini-kms:
kms-admin --tcp 127.0.0.1:9123 create-key-group ca-key
export MINICA_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
mini-ca --port 8499 --data-dir ~/.mini-ca \
  --kms-tcp 127.0.0.1:9123 --kms-key-group ca-key
# -> "CA key: wrapped under mini-kms"; ca-key.json on disk holds only a kms1: envelope.
```

## Security notes

- **EC P-256 / `SHA256withECDSA`**; leaves are short-lived (default 1 day, capped at 7) — short TTLs
  are the primary control, with revocation as the kill switch.
- **CSR proof-of-possession** is verified; the CA never sees a requester's private key.
- **No oracle**: any malformed/invalid CSR collapses to one generic `400`; admin-auth failures to
  `401`. **No secrets in logs** (no private keys, no admin token).
- **Loopback bind by default**; the CA issues the certs that secure the LAN and must not itself be
  exposed beyond loopback / a trusted proxy.
- **Atomic `0600` stores**; the CA key file holds only a mini-kms envelope when wrapping is enabled.
