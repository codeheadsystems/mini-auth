# Security track — attack & defense

> **Attack & defense (a framing track, not a re-write).** The services already ship excellent
> threat-model findings under `services/*/docs/security/` — each one is *issue → threat → fix → why →
> tests*. This track **frames and sequences** them for learning and adds the one missing piece, a
> family-wide [threat-model overview](threat-model-overview.md). It does not copy them; it links out.
> Primary audience: the security student / threat-modeler (P3), but every reader should do at least
> the invariants doc.

Read [`concepts/secure-design-invariants.md`](../concepts/secure-design-invariants.md) first — it
names the transferable reflexes (no oracles, constant-time, deny-by-default, crypto-shredding,
loopback + secrets-via-env, atomic-`0600`). The findings below are those reflexes *failing or being
defended* in concrete code.

## How to read a finding

Each linked doc follows the same shape. Read it as a case study in that order:

1. **The naive version** — what the obvious-but-wrong implementation does.
2. **The attack** — how an adversary exploits it (who, what they see, what they gain).
3. **What the code does** — the actual defense, with the before/after diff.
4. **The test that pins it** — the regression that keeps the hole closed.

Try the **predict-the-attack** exercise: read only sections 1–2, write down the exploit yourself,
*then* read the fix.

## The findings, sequenced

Grouped by the invariant they teach, easiest framing first:

### No oracles (failures must not leak *why*)

| Finding | Service | The lesson |
| --- | --- | --- |
| [No-oracle authentication](../../services/mini-directory/docs/security/01-no-oracle-authentication.md) | mini-directory | constant-time verify + a real-cost **dummy hash** so unknown-id vs wrong-secret are indistinguishable by timing. *(This is mini-idp's old credential check — it moved to the directory.)* |
| CSR rejection → one generic `400` | mini-ca | see [CSR proof-of-possession](../../services/mini-ca/docs/security/01-csr-proof-of-possession.md) — no oracle for *why* a CSR was rejected. |

### Protocol policy (a defense that's only as strong as its weakest accepted option)

| Finding | Service | The lesson |
| --- | --- | --- |
| [PKCE downgrade to `plain`](../../services/mini-oidc/docs/security/01-pkce-downgrade.md) | mini-oidc | mandatory PKCE is worthless if `plain` is *accepted* (or defaulted to). Fail closed on anything but `S256`. The compare was fine; the **policy** was the hole. |
| [Logout open-redirect](../../services/mini-oidc/docs/security/02-logout-open-redirect.md) | mini-oidc | only redirect to pre-registered URIs — an allowlist, never a reflected parameter. |

### Trust boundaries (who is allowed to *say* what)

| Finding | Service | The lesson |
| --- | --- | --- |
| [Forward-auth header trust](../../services/mini-gateway/docs/security/01-forward-auth-header-trust.md) | mini-gateway | identity headers (`X-Auth-*`) must be **always emitted** (empty when anonymous) so the proxy overwrites client-supplied spoofs; `/verify` must only be reachable by the trusted proxy. |
| [Path confusion](../../services/mini-gateway/docs/security/02-path-confusion.md) | mini-gateway | normalize the path *before* matching routes, or a `/public/../admin` slips a deny-by-default rule. |
| [CSR proof-of-possession](../../services/mini-ca/docs/security/01-csr-proof-of-possession.md) | mini-ca | prove the requester holds the private key for the public key being certified, before signing. |
| [Issuance authority](../../services/mini-ca/docs/security/02-issuance-authority.md) | mini-ca | possession ≠ entitlement: holding *a* key doesn't entitle you to a *name*. A separate boundary. |

### Resource & integrity (availability and tamper-evidence)

| Finding | Service | Status | The lesson |
| --- | --- | --- | --- |
| [Pre-auth connection exhaustion](../../services/mini-kms/docs/security/01-pre-auth-connection-exhaustion.md) | mini-kms | ✅ Fixed | bound connections + idle-timeout *before* auth, or a slow-reader DoSes the daemon. |
| [Keystore metadata integrity](../../services/mini-kms/docs/security/02-keystore-metadata-integrity.md) | mini-kms | ✅ Fixed | HMAC the at-rest metadata so offline tampering (re-enabling a destroyed key) is detected on load. |
| [Loopback-TCP local exposure](../../services/mini-kms/docs/security/03-loopback-tcp-local-exposure.md) | mini-kms | ⚠️ **Open** | loopback is reachable by *every local user* — a documented, still-open item. Honesty about residual risk is part of the model. |

## The capstone: the whole-family view

The findings above are per-service. The piece the repo lacked is the **trust boundaries in one
place** — why a `SCOPE` route rejects a session, where each secret lives, what each service trusts
its neighbor to have already checked. That's [`threat-model-overview.md`](threat-model-overview.md).

> Several findings are **defenses against designed-but-not-wired** assumptions. Before treating any
> of them as a live runtime guarantee, check it against
> [`concepts/honest-seams.md`](../concepts/honest-seams.md).
