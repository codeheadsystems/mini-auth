# 02 — Issuance authority: any issue-token holder can mint any name

**Severity:** High in a multi-tenant trust model; accepted for a single-operator homelab CA
**Status:** ⚠️ Documented trust boundary (explicit non-goal — no name constraints)

**Affected code:**
- `ca/CertificateAuthority.java` — `issueFromCsr` (Subject + SANs), `subjectAlternativeNames`
- `server/ApiHandlers.java` — `issue` / `renew` (admin-guarded; SANs from the request body)

## What the issue is

[Proof of possession](01-csr-proof-of-possession.md) proves the requester holds
the CSR's key. It does **not** constrain *what identity* the certificate may
assert. mini-ca takes the Subject DN straight from the CSR and the SAN list
straight from the request body, with no per-caller namespace, allow-list, or
X.509 `NameConstraints`:

```java
// CertificateAuthority.issueFromCsr — Subject copied verbatim from the CSR
... issuer, serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey)
    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
    ...
final GeneralNames altNames = subjectAlternativeNames(sans);   // sans == request.sans()
```

```java
// ApiHandlers.issue — SANs are a free-form request field, decoupled from the CSR
ca.issue(request.csr(), request.sans(), config.clampLeafTtl(request.ttlSeconds()))
```

Issuance is **admin-token gated** (`/issue`, `/renew`, `/revoke` require the
bootstrap bearer token). But every "mini" that can issue uses the **same shared
admin token** — so anyone who can call `/issue` can mint a leaf for
`CN=anything`, `DNS:any.host`, or any IP, including impersonating another internal
service. The `renew` path can likewise revoke any serial it names, with no binding
between the renewed cert and the revoked one.

## The threat it poses

In a trust model where mTLS identity is supposed to mean "this is the billing
service," the CA's certificates are only as trustworthy as "who holds the issue
token." A holder of that one token can mint `CN=billing.svc` (or a wildcard SAN,
or `0.0.0.0`) and impersonate any peer — so the **issuance authority collapses to
a single shared credential**. For a multi-tenant or multi-operator CA this is a
real privilege-separation failure.

## Why it is an accepted seam here (not a bug)

mini-ca is explicitly a **single-operator homelab CA**, and its README lists "no
policy / name constraints / templated profiles" among its non-goals. For one
operator who already holds every service's keys, "any issue-token holder can mint
any name" is not a privilege boundary worth enforcing — there is only one
principal. The danger is leaving that *implicit*: a reader could assume the
admin-token gate also constrains names. It does not, and this document makes that
explicit so nobody builds multi-tenant trust on top of it unknowingly.

What **is** enforced, and keeps this safe within its scope:

- **PoP** is verified (the requester must hold the CSR key — see
  [01](01-csr-proof-of-possession.md)).
- Leaves are non-CA (`BasicConstraints(false)`, critical), with scoped KeyUsage /
  EKU, a 128-bit random serial, and a **clamped short TTL**
  (`config.clampLeafTtl`) — so even a mis-issued leaf is short-lived and
  revocable.
- The admin token is resolved from env/file (never argv), compared in constant
  time, and never logged.

## How a production CA would close it

Constrain the names a caller may request: a configured per-caller SAN/Subject
allow-list, X.509 `NameConstraints` on the issuing key, or deriving the permitted
SANs from the *authenticated caller's own identity* rather than trusting the
request body. mini-ca deliberately does none of these — it is the teaching seam
where they would plug in.

## Tests

`ca/CertificateAuthorityTest.java` asserts the issued leaf carries the requested
SANs and the CSR's Subject, is non-CA, and has a short TTL; `CaIntegrationTest`
asserts `/issue` requires the admin token (401 without it). There is no test that
*restricts* the requestable name set — by design, because there is no such
restriction.
