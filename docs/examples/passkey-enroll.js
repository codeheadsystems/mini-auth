// passkey-enroll.js — enrol a passkey for mini-oidc from the browser DevTools Console.
//
// WHY a console snippet (and not a standalone .html file): a WebAuthn ceremony is bound to the page's
// ORIGIN, and mini-oidc's server verifies that origin against its configured --rp-origin. Code pasted
// into the DevTools Console runs *in the page's origin*, so running this while a mini-oidc page is
// open makes the origin match automatically — a static file opened from disk (origin "null") or a
// different port would fail server-side verification. (This is exactly why mini-oidc serves its own
// login page; enrolment just has no shipped UI yet — an honest seam.)
//
// HOW TO USE (lab 04, step "Enrol a passkey"):
//   1. Start mini-oidc (see the lab). Open ANY mini-oidc page in Chrome at its origin, e.g.
//        http://127.0.0.1:8477/docs
//   2. Open DevTools → ⋮ (More tools) → WebAuthn → "Enable virtual authenticator environment",
//      then "Add authenticator" (defaults are fine: ctap2 / internal / resident-key + user-verif on).
//      The virtual authenticator stands in for real hardware, so the ceremony needs no security key.
//   3. Open the Console, paste this whole file, and call:  enrolPasskey('alice', 'Alice')
//      A "registered: true" log means the passkey is stored for that username. Now do the browser
//      login at the /authorize URL the lab builds.
//
// NOTE: this mirrors the base64url ↔ ArrayBuffer plumbing in mini-oidc's own login page
// (server/LoginPages). A real deployment uses pk-auth's published browser SDK
// (@pk-auth/passkeys-browser) instead of hand-rolling it.

async function enrolPasskey(username = 'alice', displayName = 'Alice') {
  const b64uToBuf = s =>
    Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
  const bufToB64u = b =>
    btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // 1. Ask mini-oidc for creation options (a fresh challenge + this user's id, RP-ID, etc.).
  const started = await (await fetch('/register/passkey/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, displayName }),
  })).json();

  // 2. Decode the server's base64url fields into the ArrayBuffers the WebAuthn API wants.
  const pk = started.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  (pk.excludeCredentials || []).forEach(c => { c.id = b64uToBuf(c.id); });

  // 3. The authenticator generates a key pair and returns the public key + attestation.
  const cred = await navigator.credentials.create({ publicKey: pk });

  // 4. Re-encode the attestation response and hand it back for verification + storage.
  const registration = {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  const res = await fetch('/register/passkey/finish', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: started.challengeId, username, registration }),
  });
  console.log('enrol', username, '→', res.status, await res.json());
  return res.ok;
}
