# Certificates and mTLS — proving identity between *workloads*

> **Concept doc (explanation).** The capstone concept behind **mini-ca**. New terms link to
> [`GLOSSARY.md`](../GLOSSARY.md#certificates-mini-ca); the rationale for shipping a small internal
> CA instead of a full PKI lives in [`DIRECTION.md`](../DIRECTION.md). There is no dedicated lab yet
> — this doc ends with a "Now read it" code tour of `services/mini-ca`'s `ca/` package instead.
> Read [`what-a-token-is.md`](what-a-token-is.md) first: a certificate is a *different* proof
> primitive for a *different* actor (a workload, not a person or a caller with a bearer token), but
> it reuses the same signature-verification idea.

If you take one idea from this doc, take this:

> **A certificate is a public key with a signed statement attached: "the CA that everyone already
> trusts vouches that this public key belongs to this name." mTLS is TLS where *both* sides present
> one of these and check the other's, so a *workload* — not a person typing a password, not a bearer
> token in a header — proves who it is using a private key it never has to send anywhere.**

---

## The problem certificates solve

Tokens (stage 2) and passkeys (stage 3.5) both answer "who is the **caller**" — a request arrives,
carrying a bearer token or having just finished a login ceremony. But **service-to-service**
traffic in a homelab has no caller in that sense: `mini-gateway` calling `mini-oidc`'s JWKS
endpoint, or one internal service calling another, is a *workload* talking to a *workload*. Neither
side is a human who can complete a passkey ceremony, and a long-lived shared secret baked into
config is exactly the kind of static credential the family's invariants try to avoid.

**mTLS (mutual TLS)** answers this: TLS's normal server-authentication handshake, run in *both*
directions. Each side holds a private key and presents a certificate; each side verifies the
other's certificate against a **trust anchor** both were configured to trust. Nothing secret ever
crosses the wire — only signatures and public keys, exactly like a token's JWS or a passkey's
assertion.

---

## What's actually inside a certificate

An [X.509](../GLOSSARY.md#certificates-mini-ca) certificate is a small signed document:

- **A public key** — the thing being vouched for.
- **A subject** — whose key this is (a distinguished name, plus modern TLS's real check, the
  [SAN](../GLOSSARY.md#certificates-mini-ca) list of DNS names/IPs the cert is valid for).
- **A validity window** (`notBefore`/`notAfter`) and a **serial number** (how revocation refers to
  it).
- **Extensions** that constrain what the key may be used for — `BasicConstraints` (is this a CA?),
  `KeyUsage`, and [EKU](../GLOSSARY.md#certificates-mini-ca) (`clientAuth`+`serverAuth` for an mTLS
  leaf).
- **A signature** over all of the above, made by the issuer's private key.

Verifying a certificate is the same offline-signature check you already know from stage 2 — "does
this signature, over these bytes, verify against this public key" — pointed at *a name* instead of
*a claim set*.

---

## The CSR → issue → verify flow

A workload never hands its private key to anyone, including the CA. Instead:

1. **The workload generates its own key pair** and keeps the private key. It builds a
   [**CSR**](../GLOSSARY.md#certificates-mini-ca) (Certificate Signing Request, PKCS#10): "here is my
   public key, here is the subject/SANs I want, and here is that whole request **self-signed** by my
   own private key."
2. **The CA verifies [proof-of-possession](../GLOSSARY.md#certificates-mini-ca) (PoP)** — checking
   the CSR's self-signature against the public key *inside* the CSR. This proves the requester
   really holds the private key matching the public key it's asking to be certified — without the
   CA ever seeing that private key.
3. **The CA issues a leaf**: same subject and public key, plus the mTLS extension set, a fresh
   random serial, and a **short TTL** — then signs the whole thing with the CA's own private key.
4. **A verifier checks the chain to root**: does the leaf's signature verify against the CA's public
   key, is the CA the verifier's configured trust anchor, is the leaf still inside its validity
   window, and (for mTLS) does the presented SAN match who the verifier expected to be talking to?
   Any failure means "don't trust this peer" — there is no partial credit.

> **Why proof-of-possession matters.** Without step 2, anyone could submit a CSR containing *your*
> public key and a subject naming *your* service — and get a valid-looking certificate for an
> identity they don't hold the private key for. PoP is what ties "I'm requesting this identity" to
> "I can prove I hold the matching secret," the same shape as a passkey's challenge-response.

---

## Why leaf TTLs are short

A CA can't "un-sign" a certificate — once issued, the signature is valid math forever. Two
mechanisms claw back a compromised or retired certificate, and mini-ca leans on the cheaper one:

- **Revocation** — the CA publishes a list of revoked serials; every verifier must fetch and check
  it. This requires a live, reachable, freshness-checked revocation channel (a CRL or OCSP
  responder) — real machinery a small homelab CA would rather not build.
- **Short TTLs** — if a leaf expires in hours or days, a leaked key is only useful for that narrow
  window, and rotation (get a new leaf before the old one expires) becomes routine rather than an
  incident response. **This is the primary control mini-ca relies on.**

> **Honest seam.** mini-ca still publishes a revocation list (`GET /revocations`) as the kill switch
> for the case a short TTL isn't fast enough — but it's a plain JSON list, not a signed DER CRL or an
> OCSP responder. See `services/mini-ca/README.md`'s non-goals: this is a deliberate, documented
> educational simplification, not an oversight.

---

## Where mini-ca fits the family

mini-ca doesn't reinvent crypto to do any of this — BouncyCastle builds and verifies the PKIX
structures, exactly the "vetted library" reflex the rest of the family follows. And mini-ca's own
CA private key is protected the same way the token plane's signing keys are: it's persisted as a
one-record `SigningKeys` document and, with `--kms-*` configured, **envelope-wrapped under
mini-kms** — the same recursive integration `envelope-encryption-and-kms.md` describes, reused
verbatim rather than rebuilt.

---

## Now read it

- **The issuing engine:** `services/mini-ca` → `ca/CertificateAuthority#issueFromCsr` — verifies
  proof-of-possession (`csr.isSignatureValid(...)`), builds the extension set (`BasicConstraints`,
  `KeyUsage`, `ExtendedKeyUsage` client+server auth, authority/subject key identifiers, SANs), and
  signs with a fresh random serial and a short TTL. One `CaIssuanceException` for any malformed or
  invalid CSR — no oracle for which check failed.
- **The root and key material:** `ca/CaKeys` — EC P-256 keygen, the self-signed root, and
  `randomSerial()`.
- **Hand-rolled PEM:** `ca/Pem` — the encode/decode this family writes itself rather than pull in a
  dependency just for base64-with-line-wraps.
- **Bootstrap and lifecycle:** `service/CaService` — mints a fresh CA on first run (else loads it),
  issues/renews/revokes, and maintains the issuance log + revocation list; the CA private key flows
  through the same `DocumentStore` SPI `KmsSigningKeyStore` implements.

There's no hands-on lab for this stage yet — read the code above with a CSR you generate yourself
(`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key -out
leaf.csr`), `POST /issue` it to mini-ca (admin-guarded; see `services/mini-ca/README.md`), and decode
what comes back (`openssl x509 -in leaf.pem -noout -text`) to see the extension set this doc
described land in a real certificate.
