package com.codeheadsystems.miniidp.directory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory.ResolvedClient;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SeededServiceAccountsTest {

  private static final String SEED = """
      [
        {"clientId": "billing", "secret": "s3cret", "audiences": ["config-server"],
         "grants": [{"action": "ENCRYPT", "resource": "billing"},
                    {"action": "token:audience", "resource": "reports-api"}]},
        {"clientId": "ops", "secret": "ops-secret", "admin": true}
      ]
      """;

  @Test
  void seededAccountsAuthenticateWithTheirGrantsAndAudiences() {
    final InMemoryServiceAccountDirectory directory = SeededServiceAccounts.parse(SEED);

    final ResolvedClient billing = directory.authenticate("billing", "s3cret".toCharArray()).orElseThrow();
    assertEquals("billing", billing.subject());
    assertEquals(Set.of("config-server", "reports-api"), billing.audiences());
    assertEquals("billing", billing.authorization().grants().get(0).keyGroup());
    assertFalse(billing.authorization().controlPlane());

    final ResolvedClient ops = directory.authenticate("ops", "ops-secret".toCharArray()).orElseThrow();
    assertTrue(ops.authorization().controlPlane());
    assertEquals(Set.of(), ops.audiences());

    assertTrue(directory.authenticate("billing", "wrong".toCharArray()).isEmpty());
  }

  @Test
  void invalidSeedsAreRejectedWithoutEchoingSecrets() {
    final IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
        () -> SeededServiceAccounts.parse("[{\"clientId\": \"x\"}]"));
    assertTrue(missing.getMessage().contains("entry 0"));
    final IllegalArgumentException notJson = assertThrows(IllegalArgumentException.class,
        () -> SeededServiceAccounts.parse("{\"secret\": \"hunter2\""));
    assertFalse(notJson.getMessage().contains("hunter2"));
    assertThrows(IllegalArgumentException.class, () -> SeededServiceAccounts.parse("{}"));
    assertThrows(IllegalArgumentException.class, () -> SeededServiceAccounts.parse(
        "[{\"clientId\": \"x\", \"secret\": \"y\", \"audiences\": [\"*\"]}]"));
  }

  @Test
  void directoryAudienceGrantsIgnoreWildcards() {
    final InMemoryServiceAccountDirectory directory = SeededServiceAccounts.parse(
        "[{\"clientId\": \"x\", \"secret\": \"y\", \"grants\": "
            + "[{\"action\": \"token:audience\", \"resource\": \"*\"}]}]");
    assertEquals(Set.of(), directory.authenticate("x", "y".toCharArray()).orElseThrow().audiences());
  }
}
