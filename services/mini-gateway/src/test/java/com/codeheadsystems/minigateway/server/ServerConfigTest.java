package com.codeheadsystems.minigateway.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.session.SessionService;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ServerConfigTest {

  @Test
  void defaultsApplyWhenNothingIsProvided() {
    final ServerConfig config = ServerConfig.resolve(new String[] {}, Map.of("HOME", "/home/x"));
    assertEquals(ServerConfig.DEFAULT_HOST, config.host());
    assertEquals(ServerConfig.DEFAULT_PORT, config.port());
    // Defaults to mini-oidc's session file, the same cookie name, and bearer disabled.
    assertTrue(config.sessionsFile().toString().endsWith("/.mini-oidc/sessions.json"));
    assertEquals(SessionService.DEFAULT_COOKIE_NAME, config.cookieName());
    assertFalse(config.bearerEnabled());
    assertEquals("rd", config.returnParam());
  }

  @Test
  void flagsOverrideAndEnableBearer() {
    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "9000", "--sessions-file", "/tmp/s.json", "--cookie-name", "sso",
        "--jwks-url", "http://oidc/jwks.json", "--issuer", "http://oidc", "--audience", "aud"}, Map.of());
    assertEquals(9000, config.port());
    assertEquals("/tmp/s.json", config.sessionsFile().toString());
    assertEquals("sso", config.cookieName());
    assertTrue(config.bearerEnabled());
    assertEquals("http://oidc", config.issuer());
  }

  @Test
  void invalidInputsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--nope"}, Map.of()));
  }
}
