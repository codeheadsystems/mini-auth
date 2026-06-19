# How-to: rotate a mini-kms KEK

> **How-to (task-oriented).** Rotate the key-encryption key (KEK) for a mini-kms key group, and
> understand what that does to ciphertext already wrapped under it. Concept:
> [`envelope-encryption-and-kms.md`](../concepts/envelope-encryption-and-kms.md).

## What KEK rotation does (and why old data still decrypts)

A key group has **versions**; the newest is *active*. `rotate-key` creates a **new active version**
and **retains the old ones**. Because **every ciphertext names the `kek_id` it was wrapped under**,
old ciphertext keeps decrypting under its (retained) old version — only *new* wraps use the new
active version. Nothing has to be re-encrypted for existing data to keep working.

```bash
# control-plane (admin) token required
KMS=services/mini-kms/client/build/install/client/bin
$KMS/kms-admin --tcp 127.0.0.1:9123 rotate-key --key signing-keys
# => rotated; active version is now v2

$KMS/kms-admin --tcp 127.0.0.1:9123 list-keys     # shows v1 (retained) + v2 (active)
```

After this, an issuer whose signing key was wrapped under `v1` **still starts fine** — mini-kms
unwraps it under `v1`, which still exists.

## Optionally re-wrap onto the new version (`reEncrypt`)

To move existing ciphertext *onto* the new active version (so you can later disable/destroy the old
one), mini-kms offers `reEncrypt`: it decrypts under the old version and re-encrypts under the active
version **inside the KMS** — the plaintext never leaves it.

- **For a file/blob:** the client CLI exposes it:
  ```bash
  $KMS/client --tcp 127.0.0.1:9123 reencrypt --key signing-keys --in old.blob --out new.blob --aad <aad>
  ```
- **In code:** `KmsSigningKeyStore.rewrap()` re-wraps every stored signing key onto the group's
  current active version (preserving each key's `kid` as AAD).

> **⚠ Wired vs. designed.** `KmsSigningKeyStore.rewrap()` is a **library method with no production
> caller** today — there is no `--kms-rewrap` flag or admin endpoint that triggers it for a running
> issuer. Re-wrapping an issuer's stored signing keys onto a new KEK version is therefore a code-level
> capability, not yet an operator command. (Existing keys keep working under the retained old version
> regardless; you only *need* rewrap before destroying that old version.) This is the kind of seam
> [`honest-seams.md`](../concepts/honest-seams.md) is about.

## Root-key (passphrase) rotation

Rotating the **root key** (re-deriving from a new passphrase and re-wrapping all KEKs under it) is a
separate, offline operation — see `mini-kms`'s `change-passphrase` admin command and
`keyring/RootKeyRotation`. The keystore's HMAC integrity is preserved across it.

## Crypto-shredding (the irreversible end)

`destroy-version` makes a version's key unrecoverable — **everything wrapped under it becomes
permanently undecryptable.** Only do this after you've confirmed nothing you still need is wrapped
under that version (i.e. after a successful re-wrap). It is intentionally one-way.

## Order of operations to fully retire a KEK version

1. `rotate-key` → new active version.
2. Re-wrap everything off the old version (`reEncrypt` / `rewrap`).
3. Confirm nothing decrypts under the old version anymore.
4. `disable-version` (reversible) → observe nothing breaks → `destroy-version` (irreversible).
