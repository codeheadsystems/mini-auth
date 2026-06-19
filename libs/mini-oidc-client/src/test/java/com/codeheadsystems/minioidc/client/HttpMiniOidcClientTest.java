package com.codeheadsystems.minioidc.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minioidc.client.model.AuthorizeRequest;
import com.codeheadsystems.minioidc.client.model.ClientRegistration;
import com.codeheadsystems.minioidc.client.model.RegisteredClient;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.minioidc.server.OidcServer;
import com.codeheadsystems.minioidc.server.ServerConfig;
import com.codeheadsystems.minitoken.jwks.Jwk;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavior proof for {@link MiniOidcClient}: boot the REAL mini-oidc on an ephemeral loopback port,
 * then assert the client reads discovery + JWKS, registers clients (the one-time secret is returned
 * once and redacted in {@code toString}), lists them without secrets, rotates the signing key (a new
 * kid appears, the old is retained), and collapses a refused admin token to {@link ClientException}.
 *
 * <p>The authorize/token chain needs a human passkey login that cannot run headlessly, so it is not
 * exercised here; the offline id_token verification is covered by the console's OidcCodePkceFlow test.
 */
class HttpMiniOidcClientTest {

  private static final String ADMIN = "oidc-admin";

  private OidcServer server;
  private MiniOidcClient client;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    // The passkey authenticators are not needed for the non-interactive endpoints this test drives
    // (discovery, JWKS, admin client registration, key rotation, health), so they are left null.
    server = OidcServer.create(config, ADMIN, new InMemoryUserDirectory(), null, null,
        Clock.systemUTC());
    server.start();
    client = MiniOidcClient.http(URI.create("http://127.0.0.1:" + server.address().getPort()), ADMIN);
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void health_reportsOk() {
    assertEquals("ok", client.health().status());
  }

  @Test
  void discovery_andJwks_arePublished() {
    assertNotNull(client.discovery().issuer());
    assertTrue(client.discovery().jwksUri().endsWith("/jwks.json"));
    assertFalse(client.jwks().keys().isEmpty(), "the OP publishes at least one signing key");
  }

  @Test
  void registerConfidentialClient_returnsTheSecretOnce_andRedactsIt() {
    final RegisteredClient registered = client.registerClient(new ClientRegistration(
        "demo", List.of("https://example.com/cb"), List.of("openid", "profile"), true));
    assertNotNull(registered.clientId());
    assertNotNull(registered.clientSecret(), "a confidential client gets a one-time secret");
    assertTrue(registered.confidential());
    // The secret must never appear in toString (no log/exception leak).
    assertFalse(registered.toString().contains(registered.clientSecret()));
    assertTrue(registered.toString().contains("<redacted>"));
    // It is listed afterwards, but never with secret material.
    assertTrue(client.listClients().stream().anyMatch(c -> c.clientId().equals(registered.clientId())));
  }

  @Test
  void registerPublicClient_hasNoSecret() {
    final RegisteredClient registered = client.registerClient(new ClientRegistration(
        "spa", List.of("https://example.com/cb"), List.of("openid"), false));
    assertNull(registered.clientSecret(), "a public (PKCE-only) client has no secret");
    assertFalse(registered.confidential());
  }

  @Test
  void rotateSigningKey_publishesNewKidAndRetainsOld() {
    final String oldKid = client.jwks().keys().get(0).keyId();
    final String activeKid = client.rotateSigningKey().activeKid();
    assertNotEquals(oldKid, activeKid);
    final Set<String> kids = new java.util.HashSet<>();
    for (final Jwk key : client.jwks().keys()) {
      kids.add(key.keyId());
    }
    assertTrue(kids.contains(activeKid), "new active kid is published");
    assertTrue(kids.contains(oldKid), "retired kid is retained");
  }

  @Test
  void refusedAdminToken_collapsesToClientException_noOracle() {
    final MiniOidcClient wrongAdmin = MiniOidcClient.http(
        URI.create("http://127.0.0.1:" + server.address().getPort()), "not-the-admin-token");
    assertThrows(ClientException.class, wrongAdmin::listClients);
    assertThrows(ClientException.class, wrongAdmin::rotateSigningKey);
  }

  @Test
  void authorizeUrl_isWellFormedWithS256() {
    final URI url = client.authorizeUrl(new AuthorizeRequest(
        "client-1", "https://example.com/cb", "openid profile", "state-x", "nonce-y",
        Pkce.generate().challenge()));
    final String s = url.toString();
    assertTrue(s.contains("/authorize?"));
    assertTrue(s.contains("response_type=code"));
    assertTrue(s.contains("code_challenge_method=S256"));
    assertTrue(s.contains("code_challenge="));
    assertTrue(s.contains("client_id=client-1"));
  }
}
