# 01 — CSR proof-of-possession

**Severity:** Critical if absent (issuing for keys the requester doesn't hold)
**Status:** ✅ Correct by design (PoP verified before signing)

**Affected code:**
- `ca/CertificateAuthority.java` — `issueFromCsr`

## What the property is

A certificate binds an identity to a **public** key. The CA must be sure the
requester actually controls the matching **private** key before it signs —
otherwise an attacker could submit someone else's public key in a CSR and obtain a
certificate for an identity whose private key they do not have. The proof is built
into PKCS#10: a CSR is **self-signed** with the very private key it asks the CA to
certify. Verifying that self-signature is *proof of possession* (PoP).

mini-ca verifies it before doing anything else with the CSR:

```java
// CertificateAuthority.issueFromCsr — verify the CSR's self-signature against its OWN public key
if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
  throw new CaIssuanceException("CSR signature is not valid");
}
```

The verifier is constructed from the CSR's *embedded* `SubjectPublicKeyInfo`, so a
valid signature proves the requester holds the private key for the exact public
key that will end up in the leaf. The CA never sees, nor needs, the private key.

## The threat it would pose if skipped

A CA that signed a CSR without checking PoP would mint a certificate for whatever
public key (and Subject) the request carried. An attacker could lift a target's
public key, wrap it in a CSR, and obtain a valid leaf — then, in an mTLS setting,
*present that leaf* while being unable to complete the TLS handshake (no private
key)… but more importantly, the CA's signature would now vouch for a key the
attacker chose, undermining every relying party that trusts the CA. Skipping PoP
is one of the most common toy-CA mistakes; this one does not make it.

## Why it works

`isSignatureValid(...getSubjectPublicKeyInfo())` ties three things together: the
key that signed the CSR, the key embedded in the CSR, and the key that goes into
the leaf are provably the same, and the signature is fresh over the CSR contents.
Possession of the private key is therefore demonstrated without it ever leaving
the requester. A malformed or wrongly-signed CSR raises `CaIssuanceException`,
which the API layer flattens to a single generic `400` (no oracle for *why* the
CSR was rejected — `server/ApiHandlers.java`).

> **Note on authority vs. possession.** PoP proves the requester holds *this*
> key. It says nothing about whether they are *entitled* to the **name** in the
> CSR — that is a separate concern, the issuance-authority trust boundary in
> [02 — issuance authority](02-issuance-authority.md).

## Tests

`ca/CertificateAuthorityTest.java` issues a leaf from a real CSR and checks it
chains to the CA and carries the requester's key/identity; it also asserts a
malformed CSR is rejected with `CaIssuanceException` (no oracle). The HTTP-level
`CaIntegrationTest` asserts a bad CSR collapses to a generic `400`.
