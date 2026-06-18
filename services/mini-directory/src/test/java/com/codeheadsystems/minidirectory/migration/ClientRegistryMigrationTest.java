package com.codeheadsystems.minidirectory.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minidirectory.model.PrincipalKind;
import com.codeheadsystems.minidirectory.model.ResolvedPrincipal;
import com.codeheadsystems.minidirectory.secret.Argon2SecretHasher;
import com.codeheadsystems.minidirectory.secret.Argon2Settings;
import com.codeheadsystems.minidirectory.secret.SecretHash;
import com.codeheadsystems.minidirectory.service.DirectoryService;
import com.codeheadsystems.minidirectory.store.DirectoryDocument;
import com.codeheadsystems.minidirectory.store.JsonStore;
import com.codeheadsystems.minidirectory.util.RandomIds;
import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Decision;
import com.codeheadsystems.minipolicy.Resource;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Migrating mini-idp's old {@code clients.json} into mini-directory: each client becomes a service
 * account that keeps its id and secret, and whose grants resolve onto a mini-policy decision. The
 * migration is idempotent.
 */
class ClientRegistryMigrationTest {

  private static final JsonMapper MAPPER = JsonMapper.builder().build();
  private static final Argon2Settings ARGON = new Argon2Settings(1024, 1, 1);
  private static final String SECRET = "the-original-client-secret";

  @TempDir
  Path dir;

  private Path clientsFile;
  private Path dataDir;

  @BeforeEach
  void setUp() throws Exception {
    dataDir = dir.resolve("directory");
    clientsFile = dir.resolve("clients.json");
    // A clients.json shaped exactly like mini-idp's: an Argon2id secret hash + a grants claim.
    final SecretHash hash = new Argon2SecretHasher(ARGON).hash(SECRET.toCharArray());
    final ObjectNode secretHash = MAPPER.createObjectNode()
        .put("algorithm", hash.algorithm()).put("saltBase64", hash.saltBase64())
        .put("hashBase64", hash.hashBase64()).put("memoryKiB", hash.memoryKiB())
        .put("iterations", hash.iterations()).put("parallelism", hash.parallelism());
    final ArrayNode operations = MAPPER.createArrayNode().add("ENCRYPT").add("DECRYPT");
    final ObjectNode group = MAPPER.createObjectNode().put("keyGroup", "billing").set("operations", operations);
    final ObjectNode authorization = MAPPER.createObjectNode().put("controlPlane", false);
    authorization.set("grants", MAPPER.createArrayNode().add(group));
    final ObjectNode client = MAPPER.createObjectNode()
        .put("clientId", "client_legacy").put("displayName", "Legacy Demo").put("enabled", true)
        .put("createdAt", 1_700_000_000L);
    client.set("secretHash", secretHash);
    client.set("authorization", authorization);
    final ObjectNode root = MAPPER.createObjectNode();
    root.set("clients", MAPPER.createArrayNode().add(client));
    Files.writeString(clientsFile, MAPPER.writeValueAsString(root));
  }

  @Test
  void migratedClientKeepsItsIdSecretAndGrantsAndResolvesToAPolicyDecision() throws Exception {
    final ClientRegistryMigration.Result result = ClientRegistryMigration.run(clientsFile, dataDir);
    assertEquals(1, result.migrated());
    assertEquals(0, result.skipped());

    final DirectoryService directory = directory();
    // Same id, same secret still authenticates (the Argon2 hash was imported verbatim).
    assertTrue(directory.getAccount("client_legacy").isPresent());
    assertEquals(PrincipalKind.SERVICE_ACCOUNT, directory.getAccount("client_legacy").get().kind());
    assertTrue(directory.authenticate("client_legacy", SECRET.toCharArray()).isPresent());
    assertFalse(directory.authenticate("client_legacy", "wrong".toCharArray()).isPresent());

    // The migrated grants resolve onto a mini-policy decision: ENCRYPT on billing is allowed.
    final ResolvedPrincipal resolved = directory.resolve("client_legacy").orElseThrow();
    assertEquals(Decision.ALLOW,
        resolved.toPolicyEngine().decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("billing")));
    assertEquals(Decision.DENY,
        resolved.toPolicyEngine().decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("payroll")));
  }

  @Test
  void migrationIsIdempotent() throws Exception {
    assertEquals(1, ClientRegistryMigration.run(clientsFile, dataDir).migrated());
    final ClientRegistryMigration.Result rerun = ClientRegistryMigration.run(clientsFile, dataDir);
    assertEquals(0, rerun.migrated(), "a re-run migrates nothing new");
    assertEquals(1, rerun.skipped(), "the already-present account is skipped");
  }

  private DirectoryService directory() {
    return new DirectoryService(
        new JsonStore<>(dataDir.resolve("directory.json"), DirectoryDocument.class),
        new Argon2SecretHasher(ARGON), new RandomIds());
  }
}
