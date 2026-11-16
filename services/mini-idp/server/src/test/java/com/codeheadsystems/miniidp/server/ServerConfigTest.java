package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
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

  @Test
  void audiencesDefaultToEdDsaAndCanBeMappedToEs256() {
    final ServerConfig none = ServerConfig.resolve(new String[] {}, Map.of());
    assertEquals(SigningAlgorithm.EDDSA, none.signingAlgorithmFor("mini-kms"));
    assertEquals(SigningAlgorithm.EDDSA, none.signingAlgorithmFor("config-server"));
    assertTrue(!none.es256Enabled());

    final ServerConfig mapped = ServerConfig.resolve(
        new String[] {"--audience-algorithm", "config-server=ES256"},
        Map.of("MINIIDP_AUDIENCE_ALGORITHMS", "other=es256, plain=EdDSA"));
    assertEquals(SigningAlgorithm.ES256, mapped.signingAlgorithmFor("config-server"));
    assertEquals(SigningAlgorithm.ES256, mapped.signingAlgorithmFor("other"));
    assertEquals(SigningAlgorithm.EDDSA, mapped.signingAlgorithmFor("plain"));
    assertEquals(SigningAlgorithm.EDDSA, mapped.signingAlgorithmFor("mini-kms"));
    assertTrue(mapped.es256Enabled());

    assertThrows(IllegalArgumentException.class, () -> ServerConfig.resolve(
        new String[] {"--audience-algorithm", "config-server"}, Map.of()));
    assertThrows(IllegalArgumentException.class, () -> ServerConfig.resolve(
        new String[] {"--audience-algorithm", "config-server=HS256"}, Map.of()));
  }

  @Test
  void anEphemeralPortRederivesOnlyADefaultIssuer() {
    final ServerConfig derived = ServerConfig.resolve(new String[] {"--port", "0"}, Map.of());
    assertEquals("http://127.0.0.1:54321", derived.withBoundPort(54321).issuer());
    assertEquals(54321, derived.withBoundPort(54321).port());

    final ServerConfig explicit = ServerConfig.resolve(
        new String[] {"--port", "0", "--issuer", "http://localhost:8455"}, Map.of());
    assertEquals("http://localhost:8455", explicit.withBoundPort(54321).issuer());
  }

  @Test
  void serviceAccountSeedFileComesFromFlagOrEnv() {
    assertEquals("/seed.json", ServerConfig.resolve(
        new String[] {}, Map.of("MINIIDP_SERVICE_ACCOUNTS_FILE", "/seed.json"))
        .serviceAccountsFilePath().toString());
    assertEquals("/flag.json", ServerConfig.resolve(
        new String[] {"--service-accounts-file", "/flag.json"}, Map.of())
        .serviceAccountsFilePath().toString());
  }
}
