# How-to: rotate the token-signing keys

> **How-to (task-oriented).** Rotate the Ed25519 keys an issuer signs tokens with, without breaking
> tokens that are already in flight. Concept: [`what-a-token-is.md`](../concepts/what-a-token-is.md)
> ("rotation and revocation").

## What rotation does (and why it's safe)

An issuer signs with **one active key** but the JWKS keeps **retired public keys published** until
they outlive the token TTL (`retiredKeyRetention` ≈ 2× TTL). So a token signed just before a rotation
still verifies — the verifier picks the right key by `kid`. Rotation needs no coordination with
verifiers: they just re-read the JWKS.

## mini-idp

```bash
# admin token via env/file, never argv
curl -fsS -X POST http://127.0.0.1:8455/admin/keys/rotate -H "Authorization: Bearer $MINIIDP_ADMIN_TOKEN"
# => { "activeKid": "k_<new>" }
```

Confirm the **old** key is still published (so in-flight tokens verify) and a **new** active key
appears:

```bash
curl -fsS http://127.0.0.1:8455/.well-known/jwks.json \
  | python3 -c 'import sys,json;print([k["kid"] for k in json.load(sys.stdin)["keys"]])'
# before: ['k_OLD']        after: ['k_OLD', 'k_NEW']
```

New tokens are signed with `k_NEW`; tokens signed with `k_OLD` keep verifying until `k_OLD` ages out
of the JWKS (then it's dropped). No verifier changes are needed.

## mini-oidc

Same model, same token plane (mini-token's `SigningKeyService`). Rotation is exposed through its admin
surface — see `services/mini-oidc/README.md` and `/docs` for the exact route. The JWKS at
`/jwks.json` carries overlapping `kid`s during the retention window, identically to mini-idp.

## Verify nothing broke

1. Issue a token **before** rotating; keep it.
2. Rotate.
3. Offline-verify the old token (lab 02's script) against the **new** JWKS — it still passes, because
   its `kid` is still published.
4. Issue a fresh token — it carries the new `kid`.

## If signing keys are wrapped under mini-kms

Rotating the **signing key** (above) is independent of rotating the **KMS KEK** that wraps it. The
issuer unwraps its (possibly new) signing key at startup regardless. To rotate the *wrapping* KEK, see
[`rotate-a-kms-kek.md`](rotate-a-kms-kek.md).

## Notes

- Retired keys are dropped once older than the retention window — don't rotate faster than your token
  TTL or you could drop a key still in use. The default retention (2× TTL) guards the normal case.
- Rotation is an **admin-plane** action (the admin token), distinct from the data-plane token a client
  uses to get a token.
