package com.codeheadsystems.minica.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ServerConfigTest {

  @Test
  void defaultsApplyWhenNothingIsProvided() {
    final ServerConfig config = ServerConfig.resolve(new String[] {}, Map.of("HOME", "/home/x"));
    assertEquals(ServerConfig.DEFAULT_HOST, config.host());
    assertEquals(ServerConfig.DEFAULT_PORT, config.port());
    assertEquals("CN=mini-ca", config.caSubject());
    assertEquals(86_400, config.defaultLeafTtl().toSeconds());
    assertEquals(604_800, config.maxLeafTtl().toSeconds());
    assertFalse(config.kmsEnabled());
  }

  @Test
  void leafTtlIsClampedToTheMax() {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--leaf-ttl-seconds", "3600", "--max-leaf-ttl-seconds", "7200"}, Map.of());
    assertEquals(3600, config.clampLeafTtl(null).toSeconds(), "null uses the default");
    assertEquals(1800, config.clampLeafTtl(1800L).toSeconds(), "a smaller request is honored");
    assertEquals(7200, config.clampLeafTtl(99_999L).toSeconds(), "an over-large request is clamped to the max");
  }

  @Test
  void kmsFlagsEnableWrapping() {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--kms-tcp", "127.0.0.1:9123", "--kms-key-group", "ca-key"}, Map.of());
    assertTrue(config.kmsEnabled());
    assertEquals("127.0.0.1", config.kmsHost());
    assertEquals(9123, config.kmsPort());
    assertEquals("ca-key", config.kmsKeyGroup());
  }

  @Test
  void invalidInputsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--nope"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--leaf-ttl-seconds", "100", "--max-leaf-ttl-seconds", "50"}, Map.of()));
  }
}
