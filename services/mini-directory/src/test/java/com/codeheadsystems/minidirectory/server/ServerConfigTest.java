package com.codeheadsystems.minidirectory.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ServerConfigTest {

  @Test
  void defaultsApplyWhenNothingIsProvided() {
    final ServerConfig config = ServerConfig.resolve(new String[] {}, Map.of());
    assertEquals(ServerConfig.DEFAULT_HOST, config.host());
    assertEquals(ServerConfig.DEFAULT_PORT, config.port());
  }

  @Test
  void envIsOverriddenByFlags() {
    final Map<String, String> env = Map.of("MINIDIR_PORT", "9000", "MINIDIR_HOST", "0.0.0.0");
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "9100"}, env);
    assertEquals(9100, config.port(), "flag must win over env");
    assertEquals("0.0.0.0", config.host(), "env applies when no flag overrides it");
  }

  @Test
  void argonCostIsConfigurable() {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--argon-memory-kib", "2048", "--argon-iterations", "2",
            "--argon-parallelism", "1"}, Map.of());
    assertEquals(2048, config.argonSettings().memoryKiB());
    assertEquals(2, config.argonSettings().iterations());
  }

  @Test
  void invalidInputsAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--unknown-flag"}, Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> ServerConfig.resolve(new String[] {"--port"}, Map.of()));
  }
}
