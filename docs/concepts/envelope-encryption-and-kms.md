# Envelope encryption & KMS — and how the family protects its own keys

> **Concept doc (explanation).** Stage 6. Anchored on **mini-kms** and the recursive integration
> (`KmsSigningKeyStore`). New terms link to [`GLOSSARY.md`](../GLOSSARY.md); rationale in
> [`DIRECTION.md`](../DIRECTION.md). Diagram: [`kms-wrap-on-save`](../diagrams/kms-wrap-on-save.md).
> Lab: [`06`](../tutorials/06-protect-the-signing-keys.md).

Stages 1–5 built a system that mints and verifies tokens. But the tokens are signed by a **private
key**, and that key has to live *somewhere*. If it sits in plaintext on disk, stealing the file means
forging any token. This stage closes that loop: **the family encrypts its own signing keys at rest,
using its own KMS.**

To get there you need one idea — envelope encryption — and one integration — wrapping the signing
keys under mini-kms.

---

## The problem envelope encryption solves

You want to encrypt data. Naively, you encrypt it directly under one master key. Two problems:

1. **The master key touches all your data.** To encrypt 10,000 things, the master key is used 10,000
   times and must be present wherever data is. Hard to protect, hard to rotate (re-encrypt
   everything).
2. **Rotation is catastrophic.** Changing the master key means decrypting and re-encrypting every
   object.

**Envelope encryption** breaks the key into a hierarchy so the master key stays small, central, and
rarely used:

```
passphrase ──Argon2id+salt──▶ root key ──wraps──▶ KEK versions ──wrap──▶ DEKs ──AES-GCM──▶ your data
  (operator)                  (in memory)         (per key group)        (per op)
```

- A fresh **DEK** (data-encryption key) encrypts each piece of data, then is itself **wrapped**
  (encrypted) under a **KEK** (key-encryption key) and zeroed.
- The KEK is wrapped under the **root key**, which is derived from the operator's **passphrase** via
  [Argon2id](../GLOSSARY.md#cryptographic-foundations) + a salt.
- Only the tiny **wrapped DEK** travels with the ciphertext. The bulk data is encrypted locally; the
  master key never touches it.

**Why this is the win:**

- **Rotation is cheap.** Rotate a KEK and you only re-wrap the (tiny) DEKs, not the bulk data — and
  each ciphertext names the `kek_id` it used, so old data still decrypts under the retained old KEK
  version.
- **Blast radius is bounded.** A leaked DEK exposes one object. The root key derives from a
  passphrase that is never stored.
- **Crypto-shredding.** Destroy a KEK version and everything wrapped under it becomes *permanently*
  unrecoverable — instant, irreversible deletion of data you can't even reach. mini-kms's
  `DestroyVersion` is intentionally one-way.

`crypto/AesGcm` is the **only** place raw symmetric crypto happens in mini-kms, with a fresh random
nonce per encryption (never caller-supplied — nonce reuse breaks GCM).

---

## Data plane vs. control plane — two tokens

mini-kms splits its operations into two planes, each with its **own token** (the
[generalization](authorization-model.md) mini-policy describes):

- **Data plane** — per-request crypto: `encrypt` / `decrypt` / `wrap` / `unwrap`. Guarded by the
  **API token**.
- **Control plane** — key management: `create` / `rotate` / `disable` / `enable` / `destroy` a key
  group. Guarded by a **separate admin token**.

The split means a compromised data-plane credential can use keys but **cannot rotate or destroy**
them, and key lifecycle is gated behind a credential most callers never hold. (This is the same
"two tokens, two planes" idea mini-idp shows with its admin vs. client credentials.)

> **⚠ Wired vs. designed.** mini-kms's data plane ships `AllowAllPolicyEngine` — *per-client* key
> authorization is designed, not wired; a token's `grants` claim doesn't yet drive a mini-kms
> decision. See [`honest-seams.md`](honest-seams.md#1) (#1, #2).

---

## The recursive integration: wrapping the signing keys

Here's the payoff. The token plane's signing keys are stored through a `DocumentStore` (stage 2's
JWKS keys live in a `SigningKeys` document). Swap the plaintext store for **`KmsSigningKeyStore`** — a
decorator that, on every save, calls mini-kms to **envelope-wrap each private key** before it hits
disk, and on load unwraps it back into memory:

```
SigningKeyService ──save──▶ KmsSigningKeyStore ──encrypt(kid as AAD)──▶ mini-kms ──▶ "kms1:<ciphertext>" on disk
```

Walk the [wrap-on-save diagram](../diagrams/kms-wrap-on-save.md). The points that matter:

- **No plaintext key touches disk.** With `--kms-tcp`/`--kms-key-group`, the private-key field on
  disk is just `kms1:<ciphertext>`. It's unwrapped only in memory, only at startup.
- **`kid` is the AAD** ([encryption context](../GLOSSARY.md#cryptographic-foundations)): each wrapped
  key is *bound* to its key id. Decrypting with the wrong `kid` fails — a wrapped blob can't be
  swapped between records.
- **It's transparent.** `SigningKeyService` deals in normal PKCS#8 and has no idea the store wraps
  anything. The decorator lives in `mini-kms:client` (not mini-token) to keep the dependency acyclic.
- **Reused verbatim** by mini-idp, mini-oidc, *and* mini-ca — whose CA private key is just a PKCS#8
  in a one-record `SigningKeys` document. One integration, four consumers.

**Why "recursive"?** The system that issues credentials is itself secured by another component of the
same family. The KMS protects the keys that sign the tokens that (one day) authorize the KMS. It's
the family eating its own dog food — and the capstone that ties envelope encryption, the
`DocumentStore` SPI, and `kid`-as-AAD together.

---

## Now read it

- **Envelope encryption:** `services/mini-kms` → its README's *key hierarchy* + *glossary* first,
  then `crypto/AesGcm` (the only raw crypto), `keyring/LocalKeyring` (passphrase → root → KEK → DEK),
  the `MasterKeyProvider` / `KeyringManager` seams, `keyring/KeystoreIntegrity` (the HMAC).
- **The recursive integration:** `services/mini-kms/client` → `KmsSigningKeyStore` (`kid` as AAD,
  the `kms1:` envelope, `rewrap` for rotation).

Lab: [`06-protect-the-signing-keys.md`](../tutorials/06-protect-the-signing-keys.md) — start mini-kms,
run an issuer with `--kms-*`, and confirm only ciphertext touches disk.
