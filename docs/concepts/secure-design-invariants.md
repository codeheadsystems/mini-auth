# Secure-design invariants — the family's reflexes

> **Concept doc (explanation). Runs parallel to every stage.** Anchored across the whole family. New
> terms link to [`GLOSSARY.md`](../GLOSSARY.md); rationale in [`DIRECTION.md`](../DIRECTION.md). The
> [`security/`](../security/) track shows these failing-and-defended in real findings.

The `mini-` family applies the same handful of rules in every service. They aren't features — they're
*reflexes*, the things a security-minded engineer does without being asked. Learn them here as
**transferable** habits; the [security findings](../security/README.md) are them in action. Each is
named the same way across services on purpose: once you recognize the pattern, you see it everywhere.

---

## 1. No oracles — failures collapse to one generic error

An **oracle** is any difference in behavior that leaks information to an attacker. The family's rule:
**a failure must not reveal *why* it failed.**

- mini-directory authentication returns the *same* result for unknown-id, wrong-secret, and
  disabled-account — and even spends Argon2 effort on a **dummy hash** for an unknown id so *timing*
  doesn't leak existence either.
- mini-idp / mini-oidc collapse every credential failure to one `invalid_client` / `invalid_grant`.
- mini-kms flattens every decrypt/keyring failure to one `DecryptionFailed`.
- mini-ca flattens any bad CSR to one generic `400`.

You verified this in lab 03: wrong secret, unknown client, **and a downed directory** all return a
byte-identical `invalid_client`. The discipline is so complete that even an *infrastructure outage*
isn't an oracle.

> **The reflex:** when you write an error path, ask "does the *difference* between this error and that
> one tell an attacker something?" If yes, merge them.

## 2. Constant-time comparison of secrets

Comparing secrets with `==` (or a normal string compare) leaks length and prefix through **timing** —
an attacker can recover a token byte by byte. The family always uses `MessageDigest.isEqual`, which
takes the same time regardless of where the mismatch is.

You'll find it in every `AdminAuthenticator` (bearer-token check), in `Argon2SecretHasher` (secret
verify), in `KeystoreIntegrity` (HMAC check), and in mini-oidc's refresh-token and CSRF checks.

> **The reflex:** any compare where one side is a secret → constant-time.

## 3. Deny by default

Authorization **fails closed.** Anything not explicitly granted is denied — enforced by *structure*,
not by remembering to add a check:

- `GrantBasedPolicyEngine` returns `DENY` when no grant matches (lab 01).
- `DenyAllPolicyEngine` is the safe default for an unconfigured generic service (vs. `AllowAllPolicyEngine`,
  appropriate *only* where another layer already gates the door — see [why both exist](authorization-model.md)).
- mini-gateway denies any path no route rule matches, and **normalizes the path before matching** so
  `..` can't smuggle a request past a rule (lab 05).

Deny-by-default is how the family enforces **least privilege** — every principal gets the minimum
authority it needs and no more (narrow grants, scoped tokens, short TTLs, no blanket wildcards). The
two-plane / two-token splits (mini-kms's data vs. control token) are the same principle: a leaked
data credential can't do control operations.

> **The reflex:** the *absence* of a rule must mean "no," never "yes." Make the default path the
> refusing path, and grant the *least* that works — never standing authority "just in case."

## 4. Secrets via env/file, never argv — and never logged

Command-line arguments are visible to every process (`ps`, `/proc`); environment is better, files
with tight permissions better still. The family takes admin/API tokens and passphrases from **env or
a file**, never an argv flag (the `resolveAdminToken` / `resolveToken` / `readPassphrase` pattern),
and treats passphrases as `char[]` that get **zeroed** after use (an immutable `String` lingers in the
heap).

And **nothing secret is logged.** Access logs record method/path/status only — never tokens,
passphrases, keys, or bodies. (You saw the bare `GET /health -> 200` lines.)

> **The reflex:** if it's a secret, it enters via env/file, lives as briefly as possible, and never
> reaches a log line.

## 5. At-rest stores are atomic + `0600` (+ integrity where it matters)

State on disk is written **atomically** (temp file → `ATOMIC_MOVE`) so a crash can't leave a
half-written file, and at mode **`0600`** so only the owner can read it. mini-idp's / mini-directory's
/ mini-gateway's `JsonStore` all do this (a `mini-common` candidate — deliberately replicated).

Where the file's *integrity* matters, it's MAC'd: mini-kms HMACs all keystore metadata
(`KeystoreIntegrity`), so offline tampering (re-enabling a destroyed key, splicing a KEK) is detected
on load — a pre-MAC keystore is rejected. And secrets stored at rest are **hashed, not kept**: session
ids as `SHA-256`, client secrets as Argon2id, refresh tokens as `SHA-256`.

> **The reflex:** write durable state atomically, lock it to the owner, and ask "what breaks if someone
> edits this file?" — MAC it if the answer is "security."

## 6. Loopback by default

Every service binds `127.0.0.1` unless an operator explicitly opts out. Exposing beyond loopback is a
deliberate decision that pulls in more requirements (TLS proxy, `--secure-cookies`). mini-gateway is
reached by its proxy over loopback/Docker networking and is **never** exposed to clients directly.

> **The reflex:** the default network surface is the smallest one. Widening it is a conscious act with
> its own checklist.

## 7. Short-lived credentials + a kill switch

Tokens and certs are deliberately **short-lived** (minutes for access tokens, short TTLs for leaves) —
that's the *primary* control, because offline-verified credentials can't be called back mid-life.
Revocation (a `jti` denylist; mini-ca's revocation list) is the *secondary* early kill switch. And
crypto-shredding (mini-kms `DestroyVersion`) is the irreversible nuclear option.

> **The reflex:** make credentials expire on their own; treat revocation as the exception, not the
> plan.

## 8. Anti-forgery on state-changing browser requests

A browser carries the user's session cookie automatically, so any cross-site page can try to make the
user's browser POST to a sensitive endpoint — a **[CSRF](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect)**
attack. mini-oidc defends every state-changing browser POST (login finish, consent decision, recovery)
two ways: a **`SameSite=Lax`** session cookie (not sent on cross-site POSTs) **and** a
per-pending-authorization **CSRF token** that must accompany the request, constant-time checked.

> **The reflex:** if a *browser* can trigger a state change while carrying ambient credentials, it
> needs an unguessable token the attacker's site can't supply.

---

## These compose

The findings in the [security track](../security/README.md) are usually *one* of these reflexes being
applied (or, in the "naive version," missing). The [PKCE-downgrade](../security/README.md) finding is
#3 (don't accept the weak option — fail closed); [forward-auth header trust](../security/README.md) is
#3 + a trust boundary — the classic **[confused-deputy](../GLOSSARY.md#architecture--patterns)** risk,
where a client forges `X-Auth-*` / `X-Forwarded-*` to make the gateway misuse its authority;
[keystore integrity](../security/README.md) is #5. Read a few findings with
this list beside you and the pattern-matching becomes automatic — which is the whole point.

## Now read it

- **No oracle / constant-time:** `services/mini-directory` → `service/DirectoryService#authenticate`
  (dummy hash) and `secret/Argon2SecretHasher`.
- **Deny by default:** `libs/mini-policy` → `GrantBasedPolicyEngine`, `DenyAllPolicyEngine`.
- **Secrets/at-rest:** any `server/ServerConfig` (`resolveAdminToken`), any `store/JsonStore` (atomic
  `0600`), `mini-kms keyring/KeystoreIntegrity` (the HMAC).

Then the [`security/` track](../security/README.md) and its
[threat-model overview](../security/threat-model-overview.md).
