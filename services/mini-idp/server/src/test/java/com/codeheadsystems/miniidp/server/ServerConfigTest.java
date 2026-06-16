package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ServerConfigTest {

  @Test
  void defaultsApplyWhenNothingIsProvided() {
    final ServerConfig config = ServerConfig.resolve(new String[] {}, Map.of());
    assertEquals(ServerConfig.DEFAULT_HOST, config.host());
    assertEquals(ServerConfig.DEFAULT_PORT, config.port());
    assertEquals(ServerConfig.DEFAULT_AUDIENCE, config.audience());
    assertEquals(ServerConfig.DEFAULT_TOKEN_TTL_SECONDS, (int) config.tokenTtl().toSeconds());
    // Default issuer is derived from the bind address.
    assertEquals("http://127.0.0.1:8455", config.issuer());
  }

  @Test
  void envIsOverriddenByFlags() {
    final Map<String, String> env = Map.of(
        "MINIIDP_PORT", "9000",
        "MINIIDP_AUDIENCE", "from-env");
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "9100", "--audience", "from-flag"}, env);
    assertEquals(9100, config.port(), "flag must win over env");
    assertEquals("from-flag", config.audience());
  }

  @Test
  void issuerTrailingSlashIsStrippedAndUrlsDerived() {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--issuer", "https://idp.example/"}, Map.of());
    assertEquals("https://idp.example", config.issuer());
    assertEquals("https://idp.example/oauth/token", config.tokenEndpoint());
    assertEquals("https://idp.example/.well-known/jwks.json", config.jwksUri());
  }

  @Test
  void retiredKeyRetentionExceedsTokenTtl() {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--token-ttl-seconds", "300"}, Map.of());
    assertTrue(config.retiredKeyRetention().toSeconds() > config.tokenTtl().toSeconds());
  }

  @Test
  void invalidInputsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--token-ttl-seconds", "0"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--unknown-flag"}, Map.of()));
  }
}
