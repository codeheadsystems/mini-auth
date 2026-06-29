# What a passkey *is* — login without a shared secret

> **Concept doc (explanation).** Stage 3.5 (the human-authentication half of stage 4). Anchored on
> **mini-oidc** (which embeds **pk-auth**). New terms link to [`GLOSSARY.md`](../GLOSSARY.md); the
> rationale for embedding pk-auth lives in [`DIRECTION.md`](../DIRECTION.md). Pairs with the lab
> [`tutorials/04-human-sso-end-to-end.md`](../tutorials/04-human-sso-end-to-end.md), where a person
> logs in with a passkey for real. Read [`what-a-token-is.md`](what-a-token-is.md) first — a passkey
> proves *who you are*; the token is what mini-oidc mints *after* that proof.

If you take one idea from this doc, take this:

> **A passkey is a key pair. The private half never leaves your device; the server only ever stores
> the public half. "Logging in" means the server sends a random challenge, your device signs it with
> the private key, and the server checks the signature against the public key it stored at sign-up —
> the same offline signature check a token uses, pointed at *authentication* instead of
> *authorization*.**

There is no shared secret to phish, reuse, or leak from a breached database. That single property is
why passkeys exist.

---

## The problem passkeys solve

A password is a **shared secret**: you know it, the server stores a hash of it, and anyone who learns
it *is* you. That makes passwords vulnerable to the whole zoo — reuse across sites, phishing pages
that capture what you type, and database breaches that leak millions of hashes to crack offline.

A passkey replaces the shared secret with **public-key cryptography** ([asymmetric
crypto](../GLOSSARY.md#cryptographic-foundations)). At sign-up your device generates a fresh key pair
*for this one site*. It keeps the **private key** (in secure hardware — a TPM, a Secure Enclave, a
security key) and hands the site only the **public key**. The site stores that public key against
your account. There is now **nothing secret on the server** to steal: a breach leaks public keys,
which are useless to an attacker.

This is [WebAuthn](../GLOSSARY.md#passkeys-webauthn) — the browser standard (W3C) that exposes this
to web pages via `navigator.credentials` — together with CTAP, the protocol to the authenticator
device. "Passkey" is the consumer-friendly name for a WebAuthn credential.

---

## Two ceremonies: registration and authentication

WebAuthn has exactly two flows, and they mirror each other. Both are **challenge–response**: the
server issues a fresh random [challenge](../GLOSSARY.md#passkeys-webauthn) and the device answers in a
way only the right private key can.

### Registration (sign-up) — `navigator.credentials.create()`

1. The server sends **creation options**: a random challenge, the [RP-ID](../GLOSSARY.md#passkeys-webauthn)
   (which site this credential is for), and your user id.
2. Your authenticator **generates a new key pair**, stores the private key, and returns the **public
   key** plus an **[attestation](../GLOSSARY.md#passkeys-webauthn)** — a signed statement, *"I, a
   genuine authenticator, just created this key for this challenge and this site."*
3. The server verifies the attestation and **stores the public key** against your account.

### Authentication (login) — `navigator.credentials.get()`

1. The server sends a fresh random challenge.
2. Your authenticator **signs the challenge** (plus some context) with the stored private key,
   producing an **[assertion](../GLOSSARY.md#passkeys-webauthn)**.
3. The server **verifies the signature** against the public key it stored at registration. Match →
   you're authenticated.

> **Attestation vs. assertion** — the two are easy to confuse. *Attestation* is produced once, at
> **registration**, and certifies *the authenticator and the new key*. *Assertion* is produced every
> **login**, and proves *possession of the private key for this challenge*. mini-oidc reads the
> verified assertion's user handle to learn who just logged in — and nothing else from pk-auth.

---

## Why a passkey resists phishing

This is the part passwords can never match, and it comes from two bindings the browser enforces — not
the user's vigilance.

- **Origin/RP-ID binding.** The browser will only invoke a credential whose RP-ID matches the
  [origin](../GLOSSARY.md#passkeys-webauthn) of the page actually in the address bar, and it stamps
  that origin into the signed data. A look-alike phishing page at `οidc.example` (a Cyrillic
  homograph) has a *different* origin, so the genuine credential simply will not fire there — and even
  a forwarded ceremony fails verification because the origin in the signature is wrong. There is no
  secret for the user to be tricked into typing into the wrong box, because **there is no secret to
  type at all.**
- **Challenge binding.** Each login signs a *fresh server-issued challenge*, so a captured assertion
  can't be replayed — it answered a one-time question. (Same idea as a token's short `exp`, enforced
  cryptographically per attempt.)

Compare this to a token (stage 2): a token's signature is checked by the *resource server* to trust a
*claim set*; a passkey's signature is checked by the *identity provider* to trust *the person at the
keyboard*. Same primitive — a signature over reproducible bytes, verified against a stored public key
— aimed at a different job.

---

## Where pk-auth fits (and where mini-oidc takes over)

mini-oidc does **not** hand-roll WebAuthn — the verification (attestation formats, signature counters,
origin checks via WebAuthn4J under the hood) is exactly the kind of crypto the "mini" ethos says to
get from a vetted library. So mini-oidc **embeds [pk-auth](../GLOSSARY.md#passkeys-webauthn)** to run
both ceremonies and to store credentials behind swappable SPIs.

The boundary is deliberate: pk-auth proves *the human is who they claim*, and mini-oidc reads only the
authenticated **user handle** off the verified assertion — it then resolves that human in
mini-directory and mints its **own** ID/access tokens through mini-token. mini-oidc never consumes
pk-auth's own JWT. So the passkey is the *front door*; everything past it is the token plane you
already know.

> **Honest seam.** In mini-oidc today, passkey **enrolment** (`/register/passkey/**`) is
> *unauthenticated self-enrolment* — anyone can enrol a credential for a username. A real deployment
> gates enrolment behind an existing session or an invite. See
> [`honest-seams.md`](honest-seams.md#3); the lab calls this out where you hit it.

---

## Now read it

- **The human-authentication seam:** `services/mini-oidc` → `auth/HumanAuthenticator` (the SPI: a
  `startRegistration`/`startAssertion` → `finish` pair returning a `Challenge`),
  `auth/PkAuthHumanAuthenticator` (the pk-auth implementation — note it reads the authenticated
  `userHandle` off the verified assertion, never pk-auth's JWT), and `auth/PasskeyStack` (assembles
  the embedded pk-auth stack over its in-memory SPIs — the documented swap point for persistent
  credential storage).
- **Recovery:** `auth/RecoveryAuthenticator` (backup codes, for a lost authenticator).
- **The browser side:** `services/mini-oidc` → `server/LoginPages` (the minimal login page whose
  inline JS does the base64url ↔ ArrayBuffer plumbing and calls `navigator.credentials.get`).

Now do the lab — [`04-human-sso-end-to-end.md`](../tutorials/04-human-sso-end-to-end.md): enrol a
passkey with a virtual authenticator, log in for real, and watch mini-oidc mint the tokens from
stage 2 *after* the passkey proves who you are. Then continue to stage 4,
[`sessions-vs-tokens.md`](sessions-vs-tokens.md).
