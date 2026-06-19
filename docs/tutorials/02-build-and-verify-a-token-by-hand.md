# Lab 02 — Build and verify a token by hand (the keystone)

> **Tutorial (hands-on, guaranteed to succeed). The keystone of the course.** Stage 2. ~20 minutes.
> You'll issue a real token, decode it, **verify its Ed25519 signature against the live JWKS
> yourself**, then flip one byte and watch verification fail. Do this lab. It is the single device
> that turns "a JWT is an opaque string I copy around" into a model you actually hold.
>
> **Concept behind it:** [`concepts/what-a-token-is.md`](../concepts/what-a-token-is.md).
> **Exact API:** mini-idp's `README.md` and `/docs` are authoritative.

## What you need

- JDK 21+, a green `./gradlew build`, `curl`.
- **Python 3 with the `cryptography` package** (`pip install cryptography`) — we use it to verify the
  signature, so you watch the math happen instead of trusting a library to hide it. (Any Ed25519
  verifier works; this one is just convenient.)

## 1. Start the directory and the issuer

A token is *about* an identity, so mini-idp reads its service accounts from mini-directory. We bring
up both. (This is the machine half of stage 0's split — the human half is stage 4.)

```bash
# from the repo root
./gradlew :services:mini-directory:installDist :services:mini-idp:server:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"   # mini-idp calls the directory's admin API

services/mini-directory/build/install/mini-directory/bin/mini-directory \
  --port 8466 --data-dir "$(mktemp -d)" &

services/mini-idp/server/build/install/server/bin/server \
  --port 8455 --data-dir "$(mktemp -d)" --directory-url http://127.0.0.1:8466 &
```

mini-idp's startup banner confirms the wiring: `issuer=http://127.0.0.1:8455 audience=mini-kms`,
`service accounts: read from mini-directory`, `signing keys: local file (plaintext, 0600)`.

```bash
DIR="http://127.0.0.1:8466"; IDP="http://127.0.0.1:8455"
```

## 2. Create a service account, then get a token

Create the machine identity in the **directory** (with one grant — `ENCRYPT` on the `grafana` key
group, the scenario thread), then exchange its credentials at the **issuer** for a token.

```bash
REG=$(curl -fsS -X POST "$DIR/admin/service-accounts" \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"displayName":"grafana-agent","admin":false,"grants":[{"action":"ENCRYPT","resource":"grafana"}]}')

CID=$(echo    "$REG" | python3 -c 'import sys,json;print(json.load(sys.stdin)["account"]["id"])')
SECRET=$(echo "$REG" | python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')
echo "client_id=$CID"   # the secret is shown exactly once — captured above

AT=$(curl -fsS -X POST "$IDP/oauth/token" \
  -d "grant_type=client_credentials&client_id=$CID&client_secret=$SECRET" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
echo "$AT"
```

The token endpoint returns the [OAuth client-credentials](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect)
response: `access_token`, `token_type: Bearer`, `expires_in: 300`, `scope: grafana:ENCRYPT`.

## 3. It's three base64url segments

```bash
echo "$AT" | awk -F. '{print "header:    "$1"\npayload:   "$2"\nsignature: "$3}'
```

Decode the first two (the third is raw signature bytes — not JSON):

```bash
python3 - "$AT" <<'PY'
import sys,base64,json
def b64u(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
h,p,sig = sys.argv[1].split(".")
print("HEADER :", json.dumps(json.loads(b64u(h)), indent=2))
print("PAYLOAD:", json.dumps(json.loads(b64u(p)), indent=2))
PY
```

```json
HEADER : { "alg": "EdDSA", "typ": "JWT", "kid": "k_4Uzm6ktjNgY" }
PAYLOAD: {
  "iss": "http://127.0.0.1:8455", "sub": "svc_XVUfv_E0e3Mp571U", "aud": "mini-kms",
  "iat": 1781833645, "nbf": 1781833645, "exp": 1781833945, "jti": "Bw09rIrYu75xJlnTMHkqUQ",
  "grants": { "control": false, "groups": [ { "keyGroup": "grafana", "operations": ["ENCRYPT"] } ] }
}
```

Two things to notice:

- The **`grants` claim** is exactly the directory grant from step 2, mapped into the token: `ENCRYPT`
  on key group `grafana`, `control: false`. The principal's authorization travels *inside* the
  signed token — this is the stage-1 resolution, carried.
- The **payload is not secret** — you just read it with no key. The only thing stopping you from
  editing `sub` and re-using it is the signature. Let's prove that.

## 4. Verify the signature yourself

Fetch the public keys and check the signature. **Predict first:** the signing input is the ASCII of
`header.payload` (the base64url *text*, before that final dot). Will the published `x` (a raw 32-byte
Ed25519 public key) verify the signature over those exact bytes?

```bash
curl -fsS "$IDP/.well-known/jwks.json"
```
```json
{ "keys": [ { "kty":"OKP","crv":"Ed25519","x":"NVGR_kkJPwWh5543mKfDo4u5mizH05afH6EDWvXdj0M",
              "use":"sig","alg":"EdDSA","kid":"k_4Uzm6ktjNgY" } ] }
```
```bash
python3 - "$AT" "$(curl -fsS $IDP/.well-known/jwks.json)" <<'PY'
import sys,base64,json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
def b64u(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
token, jwks = sys.argv[1], json.loads(sys.argv[2])
h,p,sig = token.split(".")
header = json.loads(b64u(h))
jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])  # 1. select key by kid
pub = Ed25519PublicKey.from_public_bytes(b64u(jwk["x"]))          #    raw 32-byte Ed25519 key
signing_input = (h + "." + p).encode("ascii")                     # 2. the base64url TEXT
try:
    pub.verify(b64u(sig), signing_input)                          # 3. verify
    print("SIGNATURE VALID  ✓   (kid=%s)" % header["kid"])
except InvalidSignature:
    print("SIGNATURE INVALID ✗")
PY
```
```
SIGNATURE VALID  ✓   (kid=k_4Uzm6ktjNgY)
```

You just did **offline verification**: you trusted the token without ever asking mini-idp to vouch
for it — only its published public key. That's the property the whole family is built on.

## 5. Tamper one claim — watch it fail

Now play attacker. Change `sub` to `svc_ATTACKER`, re-encode the payload (you can't re-sign — you
don't have the private key), and re-verify. **Predict the outcome before running.**

```bash
python3 - "$AT" "$(curl -fsS $IDP/.well-known/jwks.json)" <<'PY'
import sys,base64,json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
def b64u(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
token, jwks = sys.argv[1], json.loads(sys.argv[2])
h,p,sig = token.split(".")
payload = json.loads(b64u(p)); payload["sub"] = "svc_ATTACKER"          # forge a claim
tampered = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b"=").decode()
header = json.loads(b64u(h)); jwk = next(k for k in jwks["keys"] if k["kid"]==header["kid"])
pub = Ed25519PublicKey.from_public_bytes(b64u(jwk["x"]))
try:
    pub.verify(b64u(sig), (h + "." + tampered).encode("ascii"))
    print("SIGNATURE VALID  ✓  (forgery succeeded — should NOT happen)")
except InvalidSignature:
    print("SIGNATURE INVALID ✗  (tampered sub rejected — signature no longer matches the bytes)")
PY
```
```
SIGNATURE INVALID ✗  (tampered sub rejected — signature no longer matches the bytes)
```

**That's the entire security model in one line.** The signature commits to the *exact bytes* of
header+payload. Change any bit of either and the Ed25519 check fails. An attacker can read the
claims, but cannot alter one and keep a valid token, because they'd need the private signing key to
re-sign.

## 6. Bonus: no oracle on bad credentials

Back at the *issuer*, a wrong secret and an unknown client return the **same** generic error — the
endpoint never tells you *which* was wrong (no oracle):

```bash
curl -s -w "\nHTTP %{http_code}\n" -X POST "$IDP/oauth/token" \
  -d "grant_type=client_credentials&client_id=$CID&client_secret=WRONG"
# {"error":"invalid_client","error_description":"client authentication failed"}   HTTP 401
```

An unknown `client_id` gives a byte-identical response. (More in
[`concepts/secure-design-invariants.md`](../concepts/secure-design-invariants.md).)

```bash
# stop the services when done
kill %1 %2 2>/dev/null
```

## What you just learned

- A token is **claims + a signature over their exact encoded bytes.** Reading is free; forging needs
  the private key.
- **Offline verification** = select key by `kid` from the published JWKS → verify the signature over
  the base64url text → *then* trust the claims. No callback to the issuer.
- The signature **commits to the bytes**, which is why signing the base64url *text* (not re-serialized
  JSON) matters — and why one tampered claim is instantly rejected.

## Try it yourself (optional)

- Change one character of the **signature** segment instead of the payload — still invalid.
- Re-read [`what-a-token-is.md`](../concepts/what-a-token-is.md)'s "verification order" and find where
  `TokenVerifier` would reject a token whose header said `"alg":"none"` (the alg-confusion footgun).
- Wait 5 minutes (`exp` is 300s out) and verify again with a verifier that checks the time window —
  the signature still passes, but the *claims* check fails. Signature ≠ freshness.

Next: stage 3, [`03-machine-identity-end-to-end.md`](03-machine-identity-end-to-end.md) — the same
flow as a single end-to-end story, plus where it fails.
