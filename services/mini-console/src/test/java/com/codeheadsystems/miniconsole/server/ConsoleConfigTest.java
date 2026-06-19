package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Paths;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Unit tests for the trimmed console {@link ConsoleConfig} resolution. */
class ConsoleConfigTest {

  @Test
  void defaults_whenNothingProvided() {
    final ConsoleConfig config = ConsoleConfig.resolve(new String[] {}, Map.of("HOME", "/home/op"));
    assertEquals("127.0.0.1", config.host());
    assertEquals(8500, config.port());
    assertEquals(Paths.get("/home/op", ".mini-console"), config.dataDir());
    assertNull(config.adminTokenFilePath());
    assertEquals(false, config.secureCookies());
    assertEquals(ConsoleConfig.DEFAULT_SESSION_TTL_SECONDS, config.sessionTtl().toSeconds());
  }

  @Test
  void flagsOverrideEnv() {
    final Map<String, String> env = Map.of(
        "MINICONSOLE_HOST", "10.0.0.1", "MINICONSOLE_PORT", "9000", "HOME", "/home/op");
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--host", "0.0.0.0", "--port", "8765", "--secure-cookies"}, env);
    assertEquals("0.0.0.0", config.host());
    assertEquals(8765, config.port());
    assertTrue(config.secureCookies());
  }

  @Test
  void envUsedWhenNoFlag() {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {}, Map.of("MINICONSOLE_PORT", "9100", "HOME", "/home/op"));
    assertEquals(9100, config.port());
  }

  @Test
  void xdgDataHomeWins() {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {}, Map.of("XDG_DATA_HOME", "/data", "HOME", "/home/op"));
    assertEquals(Paths.get("/data", "mini-console"), config.dataDir());
  }

  @Test
  void rejectsOutOfRangePort() {
    assertThrows(IllegalArgumentException.class,
        () -> ConsoleConfig.resolve(new String[] {"--port", "70000"}, Map.of()));
  }

  @Test
  void rejectsUnknownFlag() {
    assertThrows(IllegalArgumentException.class,
        () -> ConsoleConfig.resolve(new String[] {"--nope"}, Map.of()));
  }

  @Test
  void rejectsNonPositiveSessionTtl() {
    assertThrows(IllegalArgumentException.class,
        () -> ConsoleConfig.resolve(new String[] {"--session-ttl-seconds", "0"}, Map.of()));
  }
}
