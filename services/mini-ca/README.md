# mini-ca

A small **internal certificate authority** for the homelab. It issues and renews **short-lived**
X.509 leaf certificates — for mTLS between the minis and for homelab services — from PKCS#10 CSRs,
keeps an issuance log and a revocation list, and protects its own CA private key by **wrapping it
under [mini-kms](../mini-kms)** (the same KMS-backed key store the token plane uses).

It is **educational, but homelab-functional**: real EC P-256 / ECDSA crypto via the JDK + Bouncy
Castle, loopback-bound, admin-token guarded, with no secrets in logs — but deliberately **not a full
PKI** (see [non-goals](#non-goals-what-this-is-not)). Like its siblings **mini-kms** and **mini-idp**,
the code is meant to be *read*: this README walks the concepts, the architecture, and each flow so
you can learn how a CA actually mints a certificate.

## Table of contents

- [Scope](#scope)
- [Non-goals (what this is NOT)](#non-goals-what-this-is-not)
- [Glossary — the core PKI concepts](#glossary--the-core-pki-concepts)
- [Run it](#run-it)
- [API](#api)
- [Architecture](#architecture)
- [How the flows work](#how-the-flows-work)
  - [Bootstrap: minting (or loading) the CA](#bootstrap-minting-or-loading-the-ca)
  - [Issue: signing a leaf from a CSR](#issue-signing-a-leaf-from-a-csr)
  - [Renew: a fresh leaf, revoke the old one](#renew-a-fresh-leaf-revoke-the-old-one)
  - [Verify: how a relying party validates a leaf](#verify-how-a-relying-party-validates-a-leaf)
- [The X.509 details](#the-x509-details)
- [Configuration reference](#configuration-reference)
- [Protecting the CA key under mini-kms](#protecting-the-ca-key-under-mini-kms)
- [Security notes](#security-notes)
- [Building & testing](#building--testing)

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

## Glossary — the core PKI concepts

If you are here to *learn how a CA works*, start with these. The rest of the README assumes them.

| Term | What it means here |
| --- | --- |
| **CA / root** | The authority. mini-ca has exactly one **self-signed root** certificate: it signs itself, and everyone who trusts the homelab installs it as a trust anchor. Its private key is the crown jewel — compromise it and every leaf it ever signs is forgeable. |
| **Leaf** | An end-entity certificate (a service's cert), signed *by* the CA. `CA:false` — a leaf may not sign other certs. Short-lived: expiry is the primary control. |
| **Trust anchor** | The certificate a verifier trusts *a priori* (here, the root at `GET /ca`). A leaf is trusted because it chains up to an installed anchor. |
| **CSR** (PKCS#10) | A *Certificate Signing Request*. The requester generates its **own** key pair, puts the public key + desired subject into a CSR, and **signs the CSR with its own private key**. It sends only the CSR — the private key never leaves the requester, and the CA never sees it. |
| **Proof-of-possession (PoP)** | The CSR's self-signature. By verifying the CSR is validly signed by the very public key it carries, the CA proves the requester actually holds the matching private key — so it can't request a cert for a key it doesn't control. |
| **SAN** (Subject Alternative Name) | The names a leaf is valid *for* (DNS names, IP addresses). Modern TLS verifies the SAN, not the legacy CN. mini-ca takes SANs from the issue request. |
| **EKU** (Extended Key Usage) | What the key may be used for. mTLS leaves carry both `clientAuth` and `serverAuth`, so the same cert authenticates a service whether it dials or is dialed. |
| **Serial** | A unique number the CA assigns each cert. mini-ca uses a random 128-bit serial; its **lowercase-hex** form is the handle the issuance log and revocation list key on. |
| **Revocation list vs CRL** | "This serial is no longer valid." A real PKI publishes a **signed DER CRL** (or OCSP). mini-ca publishes a plain **JSON list** at `/revocations` — same idea, no signature, deliberately simpler (see non-goals). |

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

On first start mini-ca mints a fresh CA and prints whether the key is `local file (0600)` or
`wrapped under mini-kms`; the trust anchor is at `GET /ca` and the live docs at `/docs`.

## API

`/ca`, `/revocations`, `/health`, and the docs are **public** (a verifier needs the anchor + CRL);
issuance/renewal/revocation/log require `Authorization: Bearer <admin token>`. Full contract:
`/openapi.yaml`, `/openapi.json`, Swagger UI at `/docs`.

| Method + path | Auth | Purpose |
| --- | --- | --- |
| `GET /ca` | public | The CA root certificate (PEM, `application/x-pem-file`) — the trust anchor. |
| `GET /revocations` | public | The revocation list (JSON array of `{serial, revokedAt, reason}`). |
| `GET /health` | public | Liveness (`{"status":"ok"}`). |
| `GET /openapi.yaml` · `/openapi.json` · `/docs` | public | The served spec + Swagger UI (vendored, offline). |
| `POST /issue` | admin | Issue a leaf from a CSR → `{serial, certificate, caCertificate, notAfter}` (201). |
| `POST /renew` | admin | Issue a fresh leaf; revoke the prior serial if `previousSerial` given (201). |
| `POST /revoke` | admin | Revoke a certificate by serial (idempotent, 200). |
| `GET /log` | admin | The issuance log, oldest first. |

**Request bodies.** `/issue` takes `{csr, ttlSeconds?, sans?}`; `/renew` adds `previousSerial?`;
`/revoke` takes `{serial, reason?}`. `csr` is a PEM PKCS#10 string; `sans` are DNS names or IPv4
addresses. A malformed/invalid CSR returns one generic **400** (no oracle for which check failed); a
missing/invalid admin token returns **401**.

## Architecture

One application module under the base package `com.codeheadsystems.minica`. The crypto in `ca/` is
I/O-free; the composition root is `server/CaServer`. Each HTTP request runs on a virtual thread; the
server binds loopback only.

```
ca/         the crypto, no I/O
  CaKeys                 EC P-256 keygen, the self-signed-root builder, random serial, PKCS#8/SPKI (de)serialize
  CertificateAuthority   the issuing engine: CSR --PoP verify--> mTLS leaf, signed with the CA key
  Pem                    hand-rolled PEM (RFC 7468) encode/decode — the text armor around DER
model/      public records (no private material)
  IssuedCertificate      one issuance-log entry: serial, subject, validity window, issuedAt, renewedFromSerial
  Revocation             one revocation-list entry: serial, revokedAt, reason
store/
  CaDocuments            CaCertificate / IssuanceLog / RevocationList — the public, plaintext docs
  JsonStore              atomic temp-file -> ATOMIC_MOVE -> 0600 (implements mini-token's DocumentStore SPI)
service/
  CaService              bootstraps/loads the CA, issues/renews/revokes, owns the log + revocation list
server/     the composition root + transport (copied family http/ infra)
  ServerMain             entry point: resolve config + tokens (env/file), build, bind, serve
  CaServer               wires the stores + CaService + router onto a JDK HttpServer
  ServerConfig           flags > env > defaults
  ApiHandlers            the routes; thin — all crypto lives in CaService/CertificateAuthority
  AdminAuthenticator     constant-time bearer check for the admin endpoints
  dto/Dtos               request/response records
  http/                  Router, RequestContext, HttpResponse, Json, ApiException, StaticResource
  OpenApiDocument, SwaggerUiPage   serve the contract + vendored Swagger UI
```

**On-disk state** (under `--data-dir`, all atomic + `0600`):

| File | Contents | Sensitivity |
| --- | --- | --- |
| `ca-key.json` | The CA **private key**, as a one-record mini-token `SigningKeys` document. | **Secret** — `kms1:`-wrapped when `--kms-*` is set, else plaintext-`0600`. |
| `ca-cert.json` | The self-signed root certificate (PEM) + `createdAt`. | Public (it's the trust anchor). |
| `issuance-log.json` | Every issued leaf's metadata (no keys). | Public-ish; operational. |
| `revocations.json` | The revoked serials. | Public (verifiers poll it). |

The key choice that makes mini-ca "recursive" with the rest of the family: the **CA private key is
modeled as a mini-token `SigningKeys` document** (one record, `kid = "ca"`) so it can flow through
the *exact same* `DocumentStore` SPI the token signing keys use — and therefore through
`KmsSigningKeyStore`, which envelope-encrypts it under mini-kms. The CA key is just "a private key
that must not sit plaintext on disk," which is precisely the problem mini-token + mini-kms already
solved.

## How the flows work

### Bootstrap: minting (or loading) the CA

`CaService` runs once at construction. It is the only writer of these files.

```
first run (ca-key.json or ca-cert.json absent):
    CaKeys.generate()                  -> fresh EC P-256 key pair
    CaKeys.selfSignedRoot(subject,…)   -> self-signed v3 root (CA:true, pathLen 0)
    caKeyStore.save(SigningKeys[ kid="ca", PKCS#8(privateKey) ])   <- wrapped under mini-kms if configured
    caCertStore.save(CaCertificate[ PEM(root) ])
    hold the (root cert, private key) in an in-memory CertificateAuthority

restart (both present):
    privateKey = CaKeys.decodePrivate( caKeyStore.load().keys[0].privatePkcs8Base64 )   <- unwrapped via mini-kms if wrapped
    rootCert   = parse( caCertStore.load().caCertificatePem )
    rebuild the in-memory CertificateAuthority; replay issuance-log.json + revocations.json into memory
```

The private key is unwrapped into memory exactly once, at bootstrap, and held by the
`CertificateAuthority`. With `--kms-*`, what touches the disk is only a `kms1:` envelope.

### Issue: signing a leaf from a CSR

`POST /issue` → `ApiHandlers.issue` → `CaService.issue` → `CertificateAuthority.issueFromCsr`.

```
1. admin bearer token checked (constant-time)                         [ApiHandlers]
2. parse PEM -> PKCS#10 CSR                                           [CertificateAuthority]
3. PROOF-OF-POSSESSION: verify the CSR's self-signature with the
   public key the CSR carries  ── fails ──> CaIssuanceException -> 400
4. take subject + public key FROM THE CSR (CA never sees the priv key)
5. serial = random 128-bit  (CaKeys.randomSerial)
6. validity = [now, now + clampLeafTtl(ttlSeconds)]   (TTL clamped to --max-leaf-ttl-seconds)
7. build the leaf with the mTLS extension set (see "The X.509 details")
8. sign with the CA private key (SHA256withECDSA)
9. record {serial, subject, validity, issuedAt} in the issuance log (persisted)
   -> 201 { serial, certificate(PEM), caCertificate(PEM), notAfter }
```

Any malformed CSR, bad signature, or unprocessable request collapses to a **single**
`CaIssuanceException` → generic **400** — never an oracle telling an attacker *which* check failed,
and the bad input is not echoed back.

### Renew: a fresh leaf, revoke the old one

`POST /renew` is `issue` plus rotation. The requester submits a CSR (typically a brand-new key pair)
and the `previousSerial` it is replacing:

```
newCert = issueFromCsr(csr, sans, ttl)        # same path as /issue, brand-new serial
if previousSerial present:
    revoke(previousSerial, "superseded by renewal")   # added to revocations.json
-> 201 { serial(new), certificate, caCertificate, notAfter }
```

So a renewed leaf is a *new* certificate (new serial, new validity), and the old serial lands on the
revocation list — overlap-free rotation. Revocation is idempotent: revoking an already-revoked serial
is a no-op.

### Verify: how a relying party validates a leaf

mini-ca issues; verification happens at the relying party (a service doing mTLS). The reference steps:

```
1. fetch + trust the root once:           GET /ca   -> install as trust anchor
2. on a TLS handshake, the peer presents its leaf:
     - verify leaf.signature against the root's public key   (chains to the anchor)
     - check now ∈ [leaf.notBefore, leaf.notAfter]
     - check the SAN matches the name you dialed
     - check EKU permits the role (clientAuth / serverAuth)
3. (optional) poll GET /revocations and reject the leaf if its serial is listed
```

Short TTLs are the primary control; the revocation list is the early kill-switch for a specific
outstanding leaf before its `notAfter`.

## The X.509 details

All certs are **EC P-256** (`secp256r1`) signed with **`SHA256withECDSA`** — the broadly
interoperable mTLS choice. Certificates are built with BouncyCastle's `JcaX509v3CertificateBuilder`
and converted to JDK `X509Certificate`s.

**The root** (`CaKeys.selfSignedRoot`) is a minimal v3 CA cert:

- `BasicConstraints`: **CA, `pathLen 0`** (critical) — it may sign leaves, but no intermediates.
- `KeyUsage`: **`keyCertSign | cRLSign`** (critical).
- `SubjectKeyIdentifier`.
- Random 128-bit serial; long validity (default 3650 days) — the root outlives the leaves.

**Each leaf** (`CertificateAuthority.issueFromCsr`) carries exactly:

- `BasicConstraints`: **`CA:false`** (critical) — a leaf can't sign anything.
- `KeyUsage`: **`digitalSignature | keyEncipherment`** (critical) — the mTLS usages.
- `ExtendedKeyUsage`: **`clientAuth + serverAuth`** — usable on either side of an mTLS connection.
- `AuthorityKeyIdentifier` (from the CA's public key) + `SubjectKeyIdentifier` (from the leaf's) —
  the chain-building hints.
- `SubjectAlternativeName` — the requested SANs; an entry matching `d.d.d.d` is encoded as an
  `iPAddress`, otherwise as a `dNSName`.
- Subject DN and public key **taken from the CSR**; random 128-bit serial; short, clamped validity.

PEM is hand-rolled in `Pem` (RFC 7468): `-----BEGIN <label>-----`, base64-of-DER wrapped at 64
columns, `-----END <label>-----` — keeping the wire format auditable end to end.

## Configuration reference

Flags override environment variables override defaults (mirrors the family's other `ServerConfig`s).

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `MINICA_HOST` | `127.0.0.1` | Loopback bind host. |
| `--port` | `MINICA_PORT` | `8499` | TCP port (`0` = ephemeral). |
| `--data-dir` | `MINICA_DATA_DIR` | `~/.mini-ca` (or `$XDG_DATA_HOME/mini-ca`) | Directory for the JSON stores. |
| `--admin-token-file` | `MINICA_ADMIN_TOKEN_FILE` | — | File holding the admin token (alt: `MINICA_ADMIN_TOKEN` env). |
| `--ca-subject` | `MINICA_CA_SUBJECT` | `CN=mini-ca` | CA subject DN — **fresh-bootstrap only**. |
| `--ca-validity-days` | `MINICA_CA_VALIDITY_DAYS` | `3650` | Root validity in days — **fresh-bootstrap only**. |
| `--leaf-ttl-seconds` | `MINICA_LEAF_TTL_SECONDS` | `86400` (1 day) | Default leaf lifetime when a request omits `ttlSeconds`. |
| `--max-leaf-ttl-seconds` | `MINICA_MAX_LEAF_TTL_SECONDS` | `604800` (7 days) | Cap a requested leaf lifetime is clamped to. |
| `--kms-tcp` | `MINICA_KMS_TCP` | — | `HOST:PORT` of mini-kms — wrap the CA key (optional). |
| `--kms-key-group` | `MINICA_KMS_KEY_GROUP` | — | The mini-kms key group the CA key is wrapped under. |
| `--kms-api-token-file` | `MINICA_KMS_API_TOKEN_FILE` | — | mini-kms data-plane token file (alt: `MINICA_KMS_API_TOKEN` env). |

The admin token (and the mini-kms API token, when wrapping) is resolved from its env var or
`*-token-file`, **never from a CLI argument**, and is never logged. The default leaf TTL must not
exceed the max (validated at startup). `--ca-subject` / `--ca-validity-days` only matter on the first
run — once `ca-cert.json` exists, the stored root is loaded as-is.

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

Without `--kms-*`, the CA key is stored plaintext-`0600` so the educational quickstart runs with no
mini-kms dependency.

## Security notes

- **EC P-256 / `SHA256withECDSA`**; leaves are short-lived (default 1 day, capped at 7) — short TTLs
  are the primary control, with revocation as the kill switch.
- **CSR proof-of-possession** is verified; the CA never sees a requester's private key.
- **No oracle**: any malformed/invalid CSR collapses to one generic `400`; admin-auth failures to
  `401`. **No secrets in logs** (no private keys, no admin token).
- **Loopback bind by default**; the CA issues the certs that secure the LAN and must not itself be
  exposed beyond loopback / a trusted proxy.
- **Atomic `0600` stores**; the CA key file holds only a mini-kms envelope when wrapping is enabled.

## Building & testing

```bash
./gradlew build                       # compile + all tests across the family (the CI gate)
./gradlew :services:mini-ca:test      # just mini-ca's tests
./gradlew :services:mini-ca:installDist   # runnable launcher at services/mini-ca/build/install/mini-ca/bin/mini-ca
```

The test suite covers: the CA crypto directly (`CertificateAuthorityTest` — a leaf chains to the
root, carries the CSR's identity + SANs + EKU, honors a short TTL, and a malformed CSR is rejected
without an oracle); the full HTTP flow (`CaIntegrationTest` — issue chains to the published `/ca`,
the issuance is logged, revoke shows up on `/revocations`, renew revokes the previous serial, the
admin guard returns 401, a bad CSR returns a generic 400, and `/ca` is public); the mini-kms
recursive integration (`KmsBackedCaKeyTest` — `ca-key.json` is `kms1:`-wrapped on disk yet the CA
still issues, and the wrapped key reloads across a restart); and configuration resolution
(`ServerConfigTest` — defaults, TTL clamping, the `--kms-*` flags, and rejected invalid inputs).
