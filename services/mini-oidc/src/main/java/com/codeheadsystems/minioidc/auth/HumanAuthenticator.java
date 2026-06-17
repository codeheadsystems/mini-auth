package com.codeheadsystems.minioidc.auth;

import java.util.Optional;

/**
 * The seam mini-oidc authenticates humans through — the passkey (WebAuthn) ceremony, plus passkey
 * enrolment. It is deliberately JSON-in / JSON-out so the login UI's JavaScript can pass the
 * WebAuthn options and the authenticator's response straight through, and so the OIDC handlers stay
 * independent of the credential library.
 *
 * <p>The shipped implementation, {@link PkAuthHumanAuthenticator}, embeds <b>pk-auth</b> for the
 * real WebAuthn ceremony (registration + assertion via WebAuthn4J). Recovery/fallback login methods
 * (backup codes here; magic-link / OTP share the same idea) are offered alongside through
 * {@link com.codeheadsystems.minioidc.auth.RecoveryAuthenticator}. {@link #finishAssertion} returns
 * only the authenticated username or empty — never <em>why</em> a ceremony failed (no oracle).
 */
public interface HumanAuthenticator {

  /**
   * Begin enrolling a passkey for {@code username}.
   *
   * @return the challenge id plus the WebAuthn {@code create()} options as JSON for the browser.
   */
  Challenge startRegistration(String username, String displayName);

  /**
   * Finish passkey enrolment by verifying the authenticator's attestation response.
   *
   * @return whether the credential was registered.
   */
  boolean finishRegistration(String challengeId, String username, String responseJson);

  /**
   * Begin a passkey assertion (login).
   *
   * @param username the user logging in (may be null for a discoverable-credential flow).
   * @return the challenge id plus the WebAuthn {@code get()} options as JSON for the browser.
   */
  Challenge startAssertion(String username);

  /**
   * Finish a passkey assertion by verifying the authenticator's response.
   *
   * @return the authenticated username, or empty on any failure (no oracle).
   */
  Optional<String> finishAssertion(String challengeId, String responseJson);

  /**
   * A ceremony challenge handed to the browser.
   *
   * @param challengeId the opaque challenge id (echoed back on finish).
   * @param optionsJson the WebAuthn options JSON the browser feeds to {@code navigator.credentials}.
   */
  record Challenge(String challengeId, String optionsJson) {
  }
}
