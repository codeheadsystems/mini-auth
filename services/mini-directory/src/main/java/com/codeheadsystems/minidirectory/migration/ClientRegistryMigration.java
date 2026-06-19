package com.codeheadsystems.minidirectory.migration;

import com.codeheadsystems.minidirectory.model.GrantSpec;
import com.codeheadsystems.minidirectory.secret.Argon2Settings;
import com.codeheadsystems.minidirectory.secret.Argon2SecretHasher;
import com.codeheadsystems.minidirectory.secret.SecretHash;
import com.codeheadsystems.minidirectory.service.DirectoryService;
import com.codeheadsystems.minidirectory.store.DirectoryDocument;
import com.codeheadsystems.minidirectory.store.JsonStore;
import com.codeheadsystems.minidirectory.util.RandomIds;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * One-time migration of mini-idp's old client registry ({@code clients.json}) into mini-directory as
 * service accounts. Each client record becomes a {@code SERVICE_ACCOUNT} {@code Account}, preserving
 * its id (so issued token subjects are unchanged), its Argon2id secret hash (so existing client
 * secrets keep working — the hash is imported verbatim and verified later under its own recorded
 * parameters), its enabled flag, and its authorization mapped to mini-directory grants: the
 * control-plane flag becomes {@code admin}, and each {@code grants[].operations[]} becomes a
 * {@code GrantSpec(action = operation, resource = grants[].keyGroup)} — the generalized form
 * mini-policy and mini-idp's reconstruction agree on.
 *
 * <p>Idempotent: an id already present in the directory is skipped (so a re-run after a partial
 * migration is safe). Reads {@code clients.json} as plain JSON — no dependency on mini-idp — and
 * never logs secret material (only ids and counts).
 *
 * <pre>
 *   java -cp services/mini-directory/build/install/mini-directory/lib/'*' \
 *     com.codeheadsystems.minidirectory.migration.ClientRegistryMigration \
 *     --clients-file ~/.mini-idp/clients.json --data-dir ~/.mini-directory
 * </pre>
 */
public final class ClientRegistryMigration {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ClientRegistryMigration() {
  }

  /** @param args {@code --clients-file <clients.json> --data-dir <directory data dir>}. */
  public static void main(final String[] args) {
    try {
      final Path clientsFile = required(args, "--clients-file");
      final Path dataDir = required(args, "--data-dir");
      final Result result = run(clientsFile, dataDir);
      System.out.println("Migrated " + result.migrated() + " client(s) into "
          + dataDir.resolve("directory.json") + "; skipped " + result.skipped() + " already present.");
    } catch (final IllegalArgumentException e) {
      System.err.println("Migration error: " + e.getMessage());
      System.exit(64);
    } catch (final IOException e) {
      System.err.println("I/O error: " + e.getMessage());
      System.exit(74);
    }
  }

  /**
   * Run the migration.
   *
   * @param clientsFile the mini-idp {@code clients.json}.
   * @param dataDir     the mini-directory data dir (holds/creates {@code directory.json}).
   * @return how many records were migrated and how many were skipped (already present).
   */
  public static Result run(final Path clientsFile, final Path dataDir) throws IOException {
    final DirectoryService directory = new DirectoryService(
        new JsonStore<>(dataDir.resolve("directory.json"), DirectoryDocument.class),
        new Argon2SecretHasher(Argon2Settings.defaults()), new RandomIds());

    final JsonNode root = MAPPER.readTree(Files.readAllBytes(clientsFile));
    final JsonNode clients = root.get("clients");
    int migrated = 0;
    int skipped = 0;
    if (clients != null) {
      for (final JsonNode client : clients) {
        if (importOne(directory, client)) {
          migrated++;
        } else {
          skipped++;
        }
      }
    }
    return new Result(migrated, skipped);
  }

  private static boolean importOne(final DirectoryService directory, final JsonNode client) {
    final String clientId = text(client, "clientId");
    if (clientId == null) {
      return false;
    }
    final JsonNode authorization = client.get("authorization");
    final boolean admin = authorization != null && authorization.has("controlPlane")
        && authorization.get("controlPlane").asBoolean();
    final List<GrantSpec> grants = grantsOf(authorization);
    final SecretHash secretHash = secretHashOf(client.get("secretHash"));
    final boolean enabled = !client.has("enabled") || client.get("enabled").asBoolean();
    try {
      directory.importServiceAccount(clientId, text(client, "displayName"), admin, enabled,
          List.of(), List.of(), grants, secretHash);
      return true;
    } catch (final IllegalStateException alreadyExists) {
      return false; // idempotent re-run
    }
  }

  /** Map a mini-idp {@code Authorization} ({control + grants[].operations}) to flat GrantSpecs. */
  private static List<GrantSpec> grantsOf(final JsonNode authorization) {
    final List<GrantSpec> grants = new ArrayList<>();
    if (authorization == null || authorization.get("grants") == null) {
      return grants;
    }
    for (final JsonNode group : authorization.get("grants")) {
      final String keyGroup = text(group, "keyGroup");
      final JsonNode operations = group.get("operations");
      if (keyGroup == null || operations == null) {
        continue;
      }
      for (final JsonNode op : operations) {
        grants.add(new GrantSpec(op.asString(), keyGroup));
      }
    }
    return grants;
  }

  private static SecretHash secretHashOf(final JsonNode node) {
    if (node == null) {
      return null;
    }
    return new SecretHash(text(node, "algorithm"), text(node, "saltBase64"), text(node, "hashBase64"),
        node.get("memoryKiB").asInt(), node.get("iterations").asInt(), node.get("parallelism").asInt());
  }

  private static String text(final JsonNode node, final String field) {
    return node.has(field) && !node.get(field).isNull() ? node.get(field).asString() : null;
  }

  private static Path required(final String[] args, final String flag) {
    for (int i = 0; i < args.length - 1; i++) {
      if (args[i].equals(flag)) {
        return Paths.get(args[i + 1]);
      }
    }
    throw new IllegalArgumentException("missing required flag " + flag);
  }

  /**
   * The migration outcome.
   *
   * @param migrated how many client records were imported as service accounts.
   * @param skipped  how many were skipped because their id already existed (idempotent re-run).
   */
  public record Result(int migrated, int skipped) {
  }
}
