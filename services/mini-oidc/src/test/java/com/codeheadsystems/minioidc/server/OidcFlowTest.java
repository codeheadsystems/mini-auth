package com.codeheadsystems.minioidc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minioidc.auth.PasskeyStack;
import com.codeheadsystems.minioidc.directory.DirectoryUser;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.minioidc.service.ScopeAuthorizer;
import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import com.codeheadsystems.minioidc.support.MutableClock;
import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Resource;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.json.PkAuthObjectMappers;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * End-to-end OIDC: a registered client completes an authorization-code + PKCE login backed by a real
 * pk-auth passkey ceremony (driven by the testkit's {@link FakeAuthenticator}, no browser), receives
 * offline-verifiable ID + access tokens, calls userinfo, refreshes, and logs out — plus the rejection
 * cases (bad PKCE, expired code, replayed code, wrong audience).
 */
class OidcFlowTest {

  private static final String ISSUER = "http://oidc.test";
  private static final String ADMIN_TOKEN = "admin-token";
  private static final String REDIRECT = "https://client.example/cb";
  private static final String CHALLENGE_ID_FIELD = "challengeId";
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final JsonMapper PK = PkAuthObjectMappers.create();

  private MutableClock clock;
  private OidcServer server;
  private FakeAuthenticator authenticator;
  private PasskeyStack passkeys;
  private HttpClient client;
  private String baseUrl;
  private String clientId;
  private String sessionCookie;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    clock = new MutableClock(Instant.parse("2026-06-17T12:00:00Z"));
    // The RP identity pk-auth validates ceremonies against; the fake authenticator matches it.
    final RelyingPartyConfig rp = new RelyingPartyConfig("example.com", "mini-oidc",
        Set.of("https://example.com"));
    passkeys = PasskeyStack.inMemory(rp, ClockProvider.system());
    authenticator = FakeAuthenticator.builder()
        .rpId("example.com").origin("https://example.com")
        .withUserVerified(true).withUserPresent(true).build();

    // "alice" resolves (via the in-memory directory) to a principal granted the profile+email scopes.
    final InMemoryUserDirectory directory = new InMemoryUserDirectory().put(new DirectoryUser(
        "alice", false,
        List.of(new Grant(Action.of("profile"), ScopeAuthorizer.SCOPE_RESOURCE),
            new Grant(Action.of("email"), ScopeAuthorizer.SCOPE_RESOURCE)),
        "Alice", "alice@example.com", true));

    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "0", "--issuer", ISSUER, "--data-dir", dir.toString(),
        "--code-ttl-seconds", "60",
        "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"}, Map.of());
    server = OidcServer.create(config, ADMIN_TOKEN, directory,
        passkeys.humanAuthenticator(), passkeys.recoveryAuthenticator(), clock);
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    clientId = registerPublicClient();
    enrollPasskey("alice");
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  // ---- The happy path ------------------------------------------------------------------------

  @Test
  void passkeyLoginYieldsVerifiableTokensRefreshesAndLogsOut() throws Exception {
    final String verifier = "verifier-0123456789-0123456789-0123456789-abc";
    final String code = loginAndAuthorize(s256(verifier), "n-0S6_WzA2Mj");

    final JsonNode tokenResponse = exchangeCode(code, verifier);
    assertEquals("Bearer", tokenResponse.get("token_type").asText());
    final String idToken = tokenResponse.get("id_token").asText();
    final String accessToken = tokenResponse.get("access_token").asText();
    final String refreshToken = tokenResponse.get("refresh_token").asText();

    // ID token verifies offline against the published JWKS, for this client, with our claims.
    final JsonNode idClaims = verify(idToken, clientId).orElseThrow();
    assertEquals("alice", idClaims.get("sub").asText());
    assertEquals(ISSUER, idClaims.get("iss").asText());
    assertEquals("n-0S6_WzA2Mj", idClaims.get("nonce").asText());
    assertEquals("Alice", idClaims.get("name").asText());
    assertEquals("alice@example.com", idClaims.get("email").asText());

    // Access token verifies for the userinfo audience and drives /userinfo.
    assertTrue(verify(accessToken, ISSUER + "/userinfo").isPresent());
    final JsonNode userinfo = MAPPER.readTree(get("/userinfo", "Bearer " + accessToken).body());
    assertEquals("alice", userinfo.get("sub").asText());
    assertEquals("alice@example.com", userinfo.get("email").asText());

    // Refresh rotates to a new, verifiable access token and a new refresh token.
    final JsonNode refreshed = MAPPER.readTree(postForm("/token",
        "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + enc(refreshToken)).body());
    final String rotatedAccess = refreshed.get("access_token").asText();
    final String rotatedRefresh = refreshed.get("refresh_token").asText();
    assertNotEquals(refreshToken, rotatedRefresh, "refresh tokens rotate");
    assertTrue(verify(rotatedAccess, ISSUER + "/userinfo").isPresent());

    // The old (used) refresh token is now a replay → rejected (and its family scorched).
    assertEquals(400, postForm("/token",
        "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + enc(refreshToken)).statusCode());

    // Single logout: session cleared, refresh family revoked.
    assertEquals(200, get("/logout", null).statusCode());
    assertEquals(400, postForm("/token",
        "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + enc(rotatedRefresh)).statusCode());
  }

  // ---- Rejection cases -----------------------------------------------------------------------

  @Test
  void wrongPkceVerifierIsRejected() throws Exception {
    final String code = loginAndAuthorize(s256("the-real-verifier-the-real-verifier-xxxxx"), null);
    final HttpResponse<String> response = postForm("/token", "grant_type=authorization_code"
        + "&client_id=" + clientId + "&redirect_uri=" + enc(REDIRECT)
        + "&code=" + enc(code) + "&code_verifier=" + enc("a-different-verifier-aaaaaaaaaaaaaaaaa"));
    assertEquals(400, response.statusCode());
    assertEquals("invalid_grant", MAPPER.readTree(response.body()).get("error").asText());
  }

  @Test
  void expiredCodeIsRejected() throws Exception {
    final String verifier = "verifier-for-expiry-verifier-for-expiry-xx";
    final String code = loginAndAuthorize(s256(verifier), null);
    clock.advance(Duration.ofSeconds(120)); // past the 60s code TTL
    assertEquals(400, exchangeCodeRaw(code, verifier).statusCode());
  }

  @Test
  void replayedCodeIsRejected() throws Exception {
    final String verifier = "verifier-for-replay-verifier-for-replay-xx";
    final String code = loginAndAuthorize(s256(verifier), null);
    assertEquals(200, exchangeCodeRaw(code, verifier).statusCode(), "first redemption succeeds");
    assertEquals(400, exchangeCodeRaw(code, verifier).statusCode(), "second redemption is a replay");
  }

  @Test
  void idTokenForTheWrongAudienceFailsVerification() throws Exception {
    final String verifier = "verifier-for-aud-verifier-for-aud-xxxxxxxx";
    final String idToken = exchangeCode(loginAndAuthorize(s256(verifier), null), verifier)
        .get("id_token").asText();
    assertTrue(verify(idToken, clientId).isPresent(), "valid for its real audience");
    assertTrue(verify(idToken, "some-other-client").isEmpty(), "rejected for a different audience");
  }

  @Test
  void backupCodeRecoveryIsAFallbackLogin() throws Exception {
    // pk-auth issues view-once backup codes for alice; one redeems as a fallback login.
    final List<String> backupCodes = passkeys.recoveryAuthenticator().generateBackupCodes("alice");
    final String verifier = "verifier-for-recovery-verifier-for-recover";

    final String loginHtml = get(authorizeUrl(s256(verifier), null), null).body();
    final String requestId = extract(loginHtml, "requestId");
    final String csrf = extract(loginHtml, "csrf");

    final HttpResponse<String> recovered = postForm("/login/recovery",
        "requestId=" + enc(requestId) + "&csrf=" + enc(csrf)
            + "&username=alice&code=" + enc(backupCodes.get(0)));
    assertEquals(302, recovered.statusCode(), "a valid backup code authenticates");
    sessionCookie = sessionCookieFrom(recovered);

    final HttpResponse<String> redirect = postForm("/authorize/decision",
        "requestId=" + enc(requestId) + "&csrf=" + enc(csrf) + "&decision=approve");
    assertEquals(302, redirect.statusCode());
    final String code = extractQueryParam(redirect.headers().firstValue("Location").orElseThrow(), "code");

    final JsonNode idClaims = verify(exchangeCode(code, verifier).get("id_token").asString(), clientId).orElseThrow();
    assertEquals("alice", idClaims.get("sub").asString());

    // The code is single-use: a second redemption fails.
    final String html2 = get(authorizeUrl(s256(verifier), null), null).body();
    sessionCookie = null;
    assertEquals(401, postForm("/login/recovery", "requestId=" + enc(extract(html2, "requestId"))
        + "&csrf=" + enc(extract(html2, "csrf")) + "&username=alice&code=" + enc(backupCodes.get(0))).statusCode());
  }

  // ---- Flow helpers --------------------------------------------------------------------------

  private String authorizeUrl(final String challenge, final String nonce) {
    final StringBuilder url = new StringBuilder("/authorize?response_type=code")
        .append("&client_id=").append(enc(clientId))
        .append("&redirect_uri=").append(enc(REDIRECT))
        .append("&scope=").append(enc("openid profile email"))
        .append("&state=xyz&code_challenge=").append(enc(challenge))
        .append("&code_challenge_method=S256");
    if (nonce != null) {
      url.append("&nonce=").append(enc(nonce));
    }
    return url.toString();
  }

  /** Drive authorize → passkey login → consent, returning the authorization code. */
  private String loginAndAuthorize(final String challenge, final String nonce) throws Exception {
    final String loginHtml = get(authorizeUrl(challenge, nonce), null).body();
    final String requestId = extract(loginHtml, "requestId");
    final String csrf = extract(loginHtml, "csrf");

    // Passkey assertion: start → the fake authenticator signs the challenge → finish.
    final StartAuthenticationResponse start = PK.readValue(
        postJson("/login/passkey/start",
            "{\"requestId\":\"" + requestId + "\",\"username\":\"alice\"}").body(),
        StartAuthenticationResponse.class);
    final UserHandle handle = passkeys.users().findHandleByUsername("alice").orElseThrow();
    final String assertion = PK.writeValueAsString(authenticator.createAssertionResponse(start, handle));
    final HttpResponse<String> finished = postJson("/login/passkey/finish",
        "{\"requestId\":\"" + requestId + "\",\"csrf\":\"" + csrf + "\",\""
            + CHALLENGE_ID_FIELD + "\":\"" + start.challengeId().value() + "\",\"assertion\":" + assertion + "}");
    assertEquals(200, finished.statusCode(), "passkey assertion must authenticate");
    sessionCookie = sessionCookieFrom(finished);

    // Consent → the redirect carries the code.
    final HttpResponse<String> redirect = postForm("/authorize/decision",
        "requestId=" + enc(requestId) + "&csrf=" + enc(csrf) + "&decision=approve");
    assertEquals(302, redirect.statusCode());
    final String location = redirect.headers().firstValue("Location").orElseThrow();
    assertTrue(location.startsWith(REDIRECT), "redirect to the registered URI");
    return extractQueryParam(location, "code");
  }

  private JsonNode exchangeCode(final String code, final String verifier) throws Exception {
    final HttpResponse<String> response = exchangeCodeRaw(code, verifier);
    assertEquals(200, response.statusCode(), response.body());
    return MAPPER.readTree(response.body());
  }

  private HttpResponse<String> exchangeCodeRaw(final String code, final String verifier) throws Exception {
    return postForm("/token", "grant_type=authorization_code"
        + "&client_id=" + enc(clientId) + "&redirect_uri=" + enc(REDIRECT)
        + "&code=" + enc(code) + "&code_verifier=" + enc(verifier));
  }

  private Optional<JsonNode> verify(final String token, final String audience) throws Exception {
    final JwkSet jwks = MAPPER.readValue(get("/jwks.json", null).body(), JwkSet.class);
    return JwsClaimsVerifier.verify(token, jwks, ISSUER, audience, clock, 5);
  }

  private String registerPublicClient() throws Exception {
    final HttpResponse<String> response = postJson("/admin/clients",
        "{\"name\":\"Demo\",\"redirectUris\":[\"" + REDIRECT + "\"],"
            + "\"scopes\":[\"openid\",\"profile\",\"email\"],\"confidential\":false}",
        "Bearer " + ADMIN_TOKEN);
    assertEquals(201, response.statusCode(), response.body());
    return MAPPER.readTree(response.body()).get("clientId").asText();
  }

  private void enrollPasskey(final String username) throws Exception {
    final StartRegistrationResponse start = PK.readValue(
        postJson("/register/passkey/start",
            "{\"username\":\"" + username + "\",\"displayName\":\"Alice\"}").body(),
        StartRegistrationResponse.class);
    final String registration = PK.writeValueAsString(authenticator.createRegistrationResponse(start));
    final HttpResponse<String> finished = postJson("/register/passkey/finish",
        "{\"" + CHALLENGE_ID_FIELD + "\":\"" + start.challengeId().value() + "\",\"username\":\""
            + username + "\",\"registration\":" + registration + "}");
    assertEquals(201, finished.statusCode(), finished.body());
  }

  // ---- HTTP + util ---------------------------------------------------------------------------

  private HttpResponse<String> get(final String path, final String auth) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (auth != null) {
      builder.header("Authorization", auth);
    }
    attachSession(builder);
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> postJson(final String path, final String body) throws Exception {
    return postJson(path, body, null);
  }

  private HttpResponse<String> postJson(final String path, final String body, final String auth)
      throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json").POST(BodyPublishers.ofString(body));
    if (auth != null) {
      builder.header("Authorization", auth);
    }
    attachSession(builder);
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> postForm(final String path, final String body) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(body));
    attachSession(builder);
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private void attachSession(final HttpRequest.Builder builder) {
    if (sessionCookie != null) {
      builder.header("Cookie", sessionCookie);
    }
  }

  private static String sessionCookieFrom(final HttpResponse<String> response) {
    for (final String setCookie : response.headers().allValues("Set-Cookie")) {
      if (setCookie.startsWith(Cookies.SESSION + "=")) {
        final String pair = setCookie.substring(0, setCookie.indexOf(';') < 0
            ? setCookie.length() : setCookie.indexOf(';'));
        return pair;
      }
    }
    return null;
  }

  private static String extract(final String html, final String field) {
    final Matcher matcher = Pattern.compile("name=\"" + field + "\" value=\"([^\"]+)\"").matcher(html);
    assertTrue(matcher.find(), "expected hidden field " + field + " in the login page");
    return matcher.group(1);
  }

  private static String extractQueryParam(final String url, final String name) {
    final Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]+)").matcher(url);
    assertTrue(matcher.find(), "expected query param " + name);
    return java.net.URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
  }

  private static String s256(final String verifier) throws Exception {
    final byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  private static String enc(final String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
