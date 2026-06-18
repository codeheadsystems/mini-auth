# Security review notes — mini-ca

These notes accompany a security review of mini-ca, in the teaching format of
`services/mini-kms/docs/security/`.

> mini-ca is an educational, single-operator homelab CA. The crypto it must get
> right, it does: CSR proof-of-possession is verified before signing, leaves are
> non-CA with scoped KeyUsage/EKU, serials are 128-bit random, leaf TTLs are
> clamped short, a bad CSR collapses to one generic 400, the admin token comes
> from env/file and is never logged, and the CA private key can be wrapped under
> mini-kms. The notes below cover one strength worth studying and one deliberate
> trust boundary worth stating out loud.

## Findings

| # | Severity | Issue | Status | Doc |
|---|----------|-------|--------|-----|
| 1 | Critical if absent | CSR proof-of-possession | ✅ Correct by design | [01](01-csr-proof-of-possession.md) |
| 2 | High (multi-tenant) / accepted (single-operator) | Issuance authority: any issue-token holder can mint any name | ⚠️ Documented trust boundary | [02](02-issuance-authority.md) |

## Known non-goals (by design)

Single self-signed root (no intermediates), a JSON revocation list rather than a
signed DER CRL or OCSP, no name constraints / templated profiles, no HSM. These
are the lines between a teaching CA and a production PKI; see the service README.
