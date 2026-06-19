package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minioidc.client.MiniOidcClient;
import com.codeheadsystems.minioidc.client.Pkce;
import com.codeheadsystems.minioidc.client.model.AuthorizeRequest;
import com.codeheadsystems.minioidc.client.model.DiscoveryDocument;
import com.codeheadsystems.minioidc.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import tools.jackson.databind.JsonNode;

/**
 * The OIDC authorization-code + PKCE exercise — prove mini-oidc's human-SSO token flow.
 *
 * <p><b>Honest about the headless limitation.</b> The full flow requires a human passkey (WebAuthn)
 * login at {@code /authorize}, which cannot be driven from a server-side smoke test. So this flow has
 * two modes:
 *
 * <ul>
 *   <li><b>Default (no code supplied):</b> it drives only the automatable parts — read discovery,
 *       fetch the JWKS, and construct a well-formed {@code /authorize} URL with PKCE {@code S256} —
 *       then marks the login + exchange step <b>SKIP</b> (never PASS), surfacing the authorize URL and
 *       the generated {@code code_verifier} so an operator can complete the login in a browser and
 *       re-run. A reader sees plainly that no login happened.</li>
 *   <li><b>Completion (code + verifier supplied):</b> exchange the code, <b>verify the id_token
 *       offline</b> against the JWKS (signature + {@code iss} + {@code aud}, and {@code nonce}/
 *       {@code auth_time} present), fetch userinfo, and refresh (asserting the rotated refresh works
 *       and the old one is refused — no-oracle replay defense).</li>
 * </ul>
 *
 * <p><b>Secret hygiene.</b> The client secret, the access/id/refresh tokens, and the authorization
 * code are never placed in a step, the summary, or a log. The PKCE {@code code_verifier} is the one
 * operator-facing value the SKIP path must surface (it is single-use and required to complete the
 * manual login); it is shown in the result for the operator and never logged.
 */
public final class OidcCodePkceFlow implements Exercise {

  /** The stable exercise id (used in the route and the result). */
  public static final String ID = "oidc-pkce";

  private static final long LEEWAY_SECONDS = 5;

  private final Clock clock;

  /** @param clock the clock used for the id_token time-window checks (injected for testability). */
  public OidcCodePkceFlow(final Clock clock) {
    this.clock = clock;
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "OIDC authorization-code + PKCE";
  }

  @Override
  public String description() {
    return "Drive mini-oidc's human-SSO flow: build a PKCE S256 authorize request and verify an "
        + "id_token offline. The passkey login is interactive, so the exchange is SKIPPED unless you "
        + "supply a code + verifier from a manual browser login.";
  }

  /**
   * Run the flow.
   *
   * @param oidc   the mini-oidc client.
   * @param inputs the operator-supplied inputs (client id, redirect URI, scope; and, for the
   *               completion path, the code + verifier + optional client secret — none retained).
   * @return the result: SKIP when the interactive login was not completed, else PASS/FAIL.
   */
  public ExerciseResult run(final MiniOidcClient oidc, final Inputs inputs) {
    final List<Step> steps = new ArrayList<>();

    final DiscoveryDocument discovery;
    try {
      discovery = oidc.discovery();
    } catch (final ClientException e) {
      steps.add(new Step("Read discovery", Status.FAIL, "could not read the OP discovery document"));
      return ExerciseResult.of(this, steps, "Could not reach the OpenID Provider.");
    }
    steps.add(new Step("Read discovery", Status.PASS, "issuer = " + discovery.issuer()));

    final JwkSet jwks;
    try {
      jwks = oidc.jwks();
    } catch (final ClientException e) {
      steps.add(new Step("Fetch JWKS", Status.FAIL, "could not fetch the published signing keys"));
      return ExerciseResult.of(this, steps, "Could not fetch the JWKS.");
    }
    steps.add(new Step("Fetch JWKS", Status.PASS, jwks.keys().size() + " signing key(s) published"));

    // If no authorization code was supplied, drive only the automatable parts and SKIP the login.
    if (inputs.code() == null || inputs.code().isBlank()) {
      final Pkce.Pair pkce = Pkce.generate();
      final URI authorizeUrl = oidc.authorizeUrl(new AuthorizeRequest(
          inputs.clientId(), inputs.redirectUri(), inputs.scope(), "harness-state",
          "harness-nonce", pkce.challenge()));
      steps.add(new Step("Build authorize URL (PKCE S256)", Status.PASS,
          "constructed a code_challenge_method=S256 authorize request"));
      steps.add(new Step("Complete passkey login + exchange", Status.SKIP,
          "interactive WebAuthn/passkey login cannot be driven headlessly. Open the authorize URL, "
              + "complete login, then re-run supplying the returned code and this code_verifier. "
              + "authorize_url=" + authorizeUrl + "  code_verifier=" + pkce.verifier()));
      return ExerciseResult.ofWithSkips(this, steps,
          "Automatable parts verified; the interactive passkey login was skipped (see the step "
              + "detail to complete it manually).");
    }

    // Completion path: exchange the operator-supplied code and verify the id_token offline.
    final TokenResponse tokens;
    try {
      tokens = oidc.exchangeCode(inputs.code(), inputs.codeVerifier(), inputs.redirectUri(),
          inputs.clientId(), blankToNull(inputs.clientSecret()));
    } catch (final ClientException e) {
      // No oracle: a bad code, a wrong verifier, and a refused client all look the same.
      steps.add(new Step("Exchange code", Status.FAIL,
          "the code exchange was refused (bad/expired code, wrong verifier, or client mismatch)"));
      return ExerciseResult.of(this, steps, "The authorization-code exchange failed.");
    }
    steps.add(new Step("Exchange code", Status.PASS,
        "received a " + tokens.tokenType() + " token (expires in " + tokens.expiresIn() + "s)"));

    if (tokens.idToken() == null || tokens.idToken().isBlank()) {
      steps.add(new Step("Verify id_token offline", Status.FAIL, "the response carried no id_token"));
      return ExerciseResult.of(this, steps, "No id_token was issued.");
    }
    // The id_token's audience is the client id (OIDC). Verify signature + iss + aud offline.
    final Optional<JsonNode> claims = JwsClaimsVerifier.verify(
        tokens.idToken(), jwks, discovery.issuer(), inputs.clientId(), clock, LEEWAY_SECONDS);
    if (claims.isEmpty()) {
      steps.add(new Step("Verify id_token offline", Status.FAIL,
          "the id_token did not verify against the JWKS (signature/iss/aud/expiry)"));
      return ExerciseResult.of(this, steps, "The id_token did NOT verify offline.");
    }
    final JsonNode body = claims.get();
    final boolean hasNonce = body.has("nonce");
    final boolean hasAuthTime = body.has("auth_time");
    steps.add(new Step("Verify id_token offline", hasNonce && hasAuthTime ? Status.PASS : Status.FAIL,
        "sub=" + textOrQuestion(body, "sub") + ", nonce " + present(hasNonce) + ", auth_time "
            + present(hasAuthTime)));

    try {
      final var info = oidc.userInfo(tokens.accessToken());
      steps.add(new Step("Fetch userinfo", Status.PASS, "sub=" + info.subject()));
    } catch (final ClientException e) {
      steps.add(new Step("Fetch userinfo", Status.FAIL, "the access token was rejected at userinfo"));
      return ExerciseResult.of(this, steps, "Userinfo rejected the access token.");
    }

    if (tokens.refreshToken() != null && !tokens.refreshToken().isBlank()) {
      try {
        final TokenResponse refreshed = oidc.refresh(tokens.refreshToken(), inputs.clientId(),
            blankToNull(inputs.clientSecret()));
        steps.add(new Step("Refresh (rotation)", Status.PASS,
            "refresh succeeded; a new " + refreshed.tokenType() + " token was issued"));
        // Replay defense: the now-rotated original refresh token must be refused (no oracle).
        boolean replayRefused;
        try {
          oidc.refresh(tokens.refreshToken(), inputs.clientId(), blankToNull(inputs.clientSecret()));
          replayRefused = false;
        } catch (final ClientException e) {
          replayRefused = true;
        }
        steps.add(new Step("Refresh replay refused", replayRefused ? Status.PASS : Status.FAIL,
            replayRefused ? "the rotated (old) refresh token was refused" : "the old refresh token "
                + "was accepted again — rotation/replay defense failed"));
      } catch (final ClientException e) {
        steps.add(new Step("Refresh (rotation)", Status.FAIL, "the refresh token was refused"));
      }
    }

    return ExerciseResult.ofWithSkips(this, steps,
        "Completed the code exchange and verified the id_token offline against the JWKS.");
  }

  private static String blankToNull(final String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static String present(final boolean present) {
    return present ? "present" : "MISSING";
  }

  private static String textOrQuestion(final JsonNode node, final String field) {
    return node.has(field) ? node.get(field).asString() : "?";
  }

  /**
   * The operator-supplied inputs for a run. The completion fields ({@code code}, {@code codeVerifier},
   * {@code clientSecret}) are optional; when {@code code} is blank the flow runs the SKIP path.
   *
   * @param clientId     the registered client id.
   * @param redirectUri  a pre-registered redirect URI.
   * @param scope        the requested scopes (space-delimited; should include {@code openid}).
   * @param clientSecret the client secret for a confidential client (completion path), or blank.
   * @param code         the authorization code from a manual browser login, or blank (SKIP path).
   * @param codeVerifier the PKCE verifier matching the code, or blank.
   */
  public record Inputs(String clientId, String redirectUri, String scope, String clientSecret,
                       String code, String codeVerifier) {
  }
}
