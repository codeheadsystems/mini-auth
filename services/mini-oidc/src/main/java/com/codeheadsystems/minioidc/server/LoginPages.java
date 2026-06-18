package com.codeheadsystems.minioidc.server;

import java.util.List;

/**
 * The minimal login and consent HTML, rendered server-side. No framework, no build step — just
 * enough to drive the passkey ceremony and capture consent, with the CSRF token threaded through
 * every state-changing POST.
 *
 * <p>The login page's inline script speaks the WebAuthn ceremony directly (start → {@code
 * navigator.credentials.get} → finish); a real deployment would use pk-auth's published browser SDK
 * ({@code @pk-auth/passkeys-browser}) instead, which handles the base64url ↔ ArrayBuffer plumbing
 * robustly. A backup-code recovery form is offered alongside as the fallback login path.
 *
 * <p>Dynamic values are escaped per context: HTML-escaped in element/attribute positions, and
 * JSON-encoded (via {@link #jsString}) where they are emitted into the inline script's string
 * literals — HTML-entity escaping is the wrong tool inside {@code <script>} and would not stop a
 * breakout. {@code requestId}/{@code csrf} are opaque base64url tokens and {@code clientName}/{@code
 * scope} come from the (operator-registered) client, but both are escaped defensively regardless.
 */
public final class LoginPages {

  private LoginPages() {
  }

  /** The login page for a pending authorization. */
  public static String login(final String requestId, final String csrf) {
    final String rid = escape(requestId);
    final String tok = escape(csrf);
    return """
        <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>mini-oidc — sign in</title></head><body>
        <h1>Sign in</h1>
        <p id="error" style="color:#b00" role="alert"></p>
        <form id="passkey" onsubmit="return signIn(event)">
          <input type="hidden" name="requestId" value="$RID"/>
          <input type="hidden" name="csrf" value="$CSRF"/>
          <label>Username <input id="username" name="username" autocomplete="username webauthn" required/></label>
          <button type="submit">Sign in with passkey</button>
        </form>
        <details><summary>Lost your passkey? Use a backup code</summary>
          <form method="post" action="/login/recovery">
            <input type="hidden" name="requestId" value="$RID"/>
            <input type="hidden" name="csrf" value="$CSRF"/>
            <label>Username <input name="username" required/></label>
            <label>Backup code <input name="code" required/></label>
            <button type="submit">Recover</button>
          </form>
        </details>
        <script>
        const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)).buffer;
        const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
        async function signIn(e) {
          e.preventDefault();
          const username = document.getElementById('username').value;
          const started = await (await fetch('/login/passkey/start', {method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({requestId:$RIDJS, username})})).json();
          const pk = started.publicKey;
          pk.challenge = b64uToBuf(pk.challenge);
          (pk.allowCredentials||[]).forEach(c => c.id = b64uToBuf(c.id));
          const cred = await navigator.credentials.get({publicKey: pk});
          const assertion = {id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            authenticatorData: bufToB64u(cred.response.authenticatorData),
            signature: bufToB64u(cred.response.signature),
            userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null}};
          const res = await fetch('/login/passkey/finish', {method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({requestId:$RIDJS, csrf:$CSRFJS, challengeId: started.challengeId, assertion})});
          if (res.ok) { window.location = (await res.json()).next; }
          else { document.getElementById('error').textContent = 'Sign-in failed.'; }
          return false;
        }
        </script></body></html>
        """
        // JS-context placeholders first (they contain "$RID"/"$CSRF" as a prefix), then the
        // HTML-attribute ones — so the attribute replace does not corrupt the script literals.
        .replace("$RIDJS", jsString(requestId)).replace("$CSRFJS", jsString(csrf))
        .replace("$RID", rid).replace("$CSRF", tok);
  }

  /** The consent page for a pending authorization, listing the scopes that would be granted. */
  public static String consent(final String requestId, final String csrf, final String clientName,
                               final List<String> scopes) {
    final StringBuilder items = new StringBuilder();
    for (final String scope : scopes) {
      items.append("<li>").append(escape(scope)).append("</li>");
    }
    return """
        <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>mini-oidc — authorize</title></head><body>
        <h1>Authorize $CLIENT</h1>
        <p><strong>$CLIENT</strong> is requesting access to:</p>
        <ul>$SCOPES</ul>
        <form method="post" action="/authorize/decision">
          <input type="hidden" name="requestId" value="$RID"/>
          <input type="hidden" name="csrf" value="$CSRF"/>
          <button type="submit" name="decision" value="approve">Allow</button>
          <button type="submit" name="decision" value="deny">Deny</button>
        </form></body></html>
        """
        .replace("$CLIENT", escape(clientName))
        .replace("$SCOPES", items.toString())
        .replace("$RID", escape(requestId))
        .replace("$CSRF", escape(csrf));
  }

  private static String escape(final String value) {
    if (value == null) {
      return "";
    }
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#39;");
  }

  /**
   * Encode a value as a JSON/JS string literal (with surrounding quotes) for safe inclusion inside
   * the inline {@code <script>}. Escapes the quote/backslash and, defensively, {@code < > &} (so a
   * value can never spell {@code </script>} or otherwise break out of the script element).
   */
  private static String jsString(final String value) {
    if (value == null) {
      return "\"\"";
    }
    final StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      final char c = value.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '<' -> out.append("\\u003c");
        case '>' -> out.append("\\u003e");
        case '&' -> out.append("\\u0026");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    return out.append('"').toString();
  }
}
