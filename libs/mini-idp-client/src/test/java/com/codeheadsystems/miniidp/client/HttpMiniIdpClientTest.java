package com.codeheadsystems.miniidp.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.miniidp.directory.InMemoryServiceAccountDirectory;
import com.codeheadsystems.miniidp.server.IdpServer;
import com.codeheadsystems.miniidp.server.ServerConfig;
import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavior proof for {@link MiniIdpClient}: boot the REAL mini-idp on an ephemeral loopback port
 * (sourcing one service account from an in-memory directory), then assert the client obtains a token
 * that verifies offline against the published JWKS, reads discovery + the audit log, and collapses a
 * wrong secret / refused admin token to {@link ClientException} (no oracle). The secret is never
 * asserted by value.
 */
class HttpMiniIdpClientTest {

  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms";
  private static final String ADMIN_TOKEN = "idp-admin";
  private static final String CLIENT = "svc_demo";
  private static final String SECRET = "s3cr3t-value";

  private IdpServer server;
  private MiniIdpClient client;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    final InMemoryServiceAccountDirectory directory = new InMemoryServiceAccountDirectory().add(
        CLIENT, SECRET, new Authorization(false,
            List.of(Grant.of("billing", KeyOperation.ENCRYPT, KeyOperation.DECRYPT))));
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--issuer", ISSUER, "--audience", AUDIENCE}, Map.of());
    server = IdpServer.create(config, ADMIN_TOKEN, directory, Clock.systemUTC());
    server.start();
    client = MiniIdpClient.http(URI.create("http://127.0.0.1:" + server.address().getPort()),
        ADMIN_TOKEN);
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
  void discovery_reportsTheConfiguredIssuer() {
    assertEquals(ISSUER, client.discovery().issuer());
  }

  @Test
  void jwks_publishesAtLeastOneKey() {
    assertFalse(client.jwks().keys().isEmpty());
  }

  @Test
  void token_returnsAnAccessTokenThatVerifiesOfflineAgainstTheJwks() {
    final TokenResponse token = client.token(CLIENT, SECRET);
    assertEquals("Bearer", token.tokenType());
    final JwkSet jwks = client.jwks();
    final TokenVerifier.Result result =
        new TokenVerifier(ISSUER, AUDIENCE, Clock.systemUTC(), 5)
            .verify(token.accessToken(), jwks, jti -> false);
    assertTrue(result.valid(), "the issued token must verify against the published JWKS");
    assertEquals(CLIENT, result.claims().subject());
  }

  @Test
  void token_wrongSecret_collapsesToClientException() {
    assertThrows(ClientException.class, () -> client.token(CLIENT, "not-the-secret"));
  }

  @Test
  void audit_recordsTokenIssuance() {
    client.token(CLIENT, SECRET);
    assertTrue(client.audit().stream().anyMatch(entry -> "token.issued".equals(entry.event())),
        "issuing a token must leave a token.issued audit entry");
  }

  @Test
  void audit_withWrongAdminToken_collapsesToClientException() {
    final MiniIdpClient badAdmin = MiniIdpClient.http(
        URI.create("http://127.0.0.1:" + server.address().getPort()), "wrong-admin-token");
    assertThrows(ClientException.class, badAdmin::audit);
  }
}
