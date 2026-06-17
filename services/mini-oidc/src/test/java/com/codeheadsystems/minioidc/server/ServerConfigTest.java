package com.codeheadsystems.minioidc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    assertEquals("http://127.0.0.1:8477", config.issuer());
    assertEquals("http://127.0.0.1:8477/userinfo", config.accessAudience());
    assertEquals("localhost", config.rpId());
    assertFalse(config.secureCookies(), "secure cookies off by default for loopback HTTP");
    // The SSO session lifetime is distinct from (and longer than) the token TTLs.
    assertTrue(config.sessionTtl().toSeconds() > config.accessTtl().toSeconds());
  }

  @Test
  void flagsOverrideEnvironment() {
    final Map<String, String> env = Map.of("MINIOIDC_PORT", "9000", "MINIOIDC_RP_ID", "from-env");
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "9100", "--rp-id", "example.com",
            "--rp-origin", "https://example.com,https://www.example.com", "--secure-cookies"},
        env);
    assertEquals(9100, config.port());
    assertEquals("example.com", config.rpId());
    assertTrue(config.rpOrigins().contains("https://example.com"));
    assertTrue(config.rpOrigins().contains("https://www.example.com"));
    assertTrue(config.secureCookies());
  }

  @Test
  void invalidInputsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--access-ttl-seconds", "0"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--nope"}, Map.of()));
  }
}
