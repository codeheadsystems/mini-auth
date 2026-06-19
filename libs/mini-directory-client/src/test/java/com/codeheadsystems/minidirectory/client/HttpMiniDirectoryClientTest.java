package com.codeheadsystems.minidirectory.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.PrincipalKind;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import com.codeheadsystems.minidirectory.server.DirectoryServer;
import com.codeheadsystems.minidirectory.server.ServerConfig;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavior proof for {@link MiniDirectoryClient}: boot the REAL mini-directory on an ephemeral
 * loopback port, seed a role → group → human through its admin API, then assert the client lists and
 * resolves them over HTTP — and that a missing principal collapses to {@link ClientException} (no
 * oracle).
 */
class HttpMiniDirectoryClientTest {

  private static final String ADMIN_TOKEN = "test-admin-token";

  private DirectoryServer server;
  private HttpClient raw;
  private String baseUrl;
  private MiniDirectoryClient client;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    // Fast Argon parameters: humans carry no secret, but the server still builds a hasher.
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"},
        Map.of());
    server = DirectoryServer.create(config, ADMIN_TOKEN);
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    raw = HttpClient.newHttpClient();
    client = MiniDirectoryClient.http(URI.create(baseUrl), ADMIN_TOKEN);

    // Seed: a role granting DECRYPT on billing, a group conferring it, and a human in that group.
    assertEquals(201, post("/admin/roles",
        "{\"id\":\"billing-reader\",\"description\":\"read billing\","
            + "\"grants\":[{\"action\":\"DECRYPT\",\"resource\":\"billing\"}]}"));
    assertEquals(201, post("/admin/groups",
        "{\"id\":\"billing-team\",\"description\":\"billing\","
            + "\"roles\":[\"billing-reader\"],\"grants\":[]}"));
    assertEquals(201, post("/admin/humans",
        "{\"id\":\"alice\",\"displayName\":\"Alice\",\"admin\":false,"
            + "\"memberOf\":[\"billing-team\"],\"roles\":[],\"grants\":[]}"));
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void health_reportsOk() {
    assertEquals("ok", client.health().status());
  }

  @Test
  void listRoles_returnsTheSeededRoleWithItsGrant() {
    assertTrue(client.listRoles().stream().anyMatch(role ->
        role.id().equals("billing-reader")
            && role.grants().contains(new GrantSpec("DECRYPT", "billing"))));
  }

  @Test
  void listGroups_returnsTheSeededGroup() {
    assertTrue(client.listGroups().stream().anyMatch(group -> group.id().equals("billing-team")));
  }

  @Test
  void listAccounts_and_getAccount_returnTheHuman() {
    assertTrue(client.listAccounts().stream().anyMatch(a -> a.id().equals("alice")));
    final Account alice = client.getAccount("alice");
    assertEquals(PrincipalKind.HUMAN, alice.kind());
    assertTrue(alice.memberOf().contains("billing-team"));
  }

  @Test
  void resolve_expandsGroupAndRoleIntoEffectiveGrants() {
    final Resolution resolution = client.resolve("alice");
    assertEquals("alice", resolution.id());
    // The (DECRYPT, billing) grant reaches alice only via group -> role expansion.
    assertTrue(resolution.grants().contains(new GrantSpec("DECRYPT", "billing")));
  }

  @Test
  void getAccount_unknown_collapsesToClientException() {
    assertThrows(ClientException.class, () -> client.getAccount("does-not-exist"));
  }

  // ---- Mutations (Slice 2) -------------------------------------------------------------------

  @Test
  void createServiceAccount_returnsAWorkingOneTimeSecret() throws Exception {
    final ServiceAccountCreated created = client.createServiceAccount(new NewServiceAccount(
        "CI bot", false, List.of("billing-team"), List.of(), List.of()));
    // The secret comes back exactly once and must be usable (structural: non-blank, and it
    // authenticates against the directory). We never assert the literal value.
    assertTrue(created.secret() != null && !created.secret().isBlank());
    assertEquals(200, post("/admin/service-accounts/authenticate",
        "{\"id\":\"" + created.id() + "\",\"secret\":\"" + created.secret() + "\"}"));
  }

  @Test
  void createHuman_thenResolveReflectsGroupExpansion() {
    final Account bob = client.createHuman(new NewHuman("bob", "Bob", false,
        List.of("billing-team"), List.of(), List.of()));
    assertEquals("bob", bob.id());
    assertTrue(client.resolve("bob").grants().contains(new GrantSpec("DECRYPT", "billing")));
  }

  @Test
  void updateAssignment_replacesAuthorizationAndResolutionFollows() {
    // Replace alice's authorization: drop the group, grant ENCRYPT:ledger directly.
    client.updateAssignment("alice", new Assignment(true, false, List.of(), List.of(),
        List.of(new GrantSpec("ENCRYPT", "ledger"))));
    final Resolution resolution = client.resolve("alice");
    assertTrue(resolution.grants().contains(new GrantSpec("ENCRYPT", "ledger")));
    // The old group-derived grant is gone (assignment replaces wholesale).
    assertTrue(resolution.grants().stream().noneMatch(g -> g.equals(new GrantSpec("DECRYPT", "billing"))));
  }

  @Test
  void deleteAccount_thenItIsGone() {
    client.deleteAccount("alice");
    assertThrows(ClientException.class, () -> client.getAccount("alice"));
  }

  @Test
  void createAndDeleteRole_roundTrips() {
    client.createRole(new NewRole("ledger-writer", "write ledger",
        List.of(new GrantSpec("ENCRYPT", "ledger"))));
    assertTrue(client.listRoles().stream().anyMatch(r -> r.id().equals("ledger-writer")));
    client.deleteRole("ledger-writer");
    assertTrue(client.listRoles().stream().noneMatch(r -> r.id().equals("ledger-writer")));
  }

  @Test
  void createAndDeleteGroup_roundTrips() {
    client.createGroup(new NewGroup("ops", "ops team", List.of(), List.of()));
    assertTrue(client.listGroups().stream().anyMatch(g -> g.id().equals("ops")));
    client.deleteGroup("ops");
    assertTrue(client.listGroups().stream().noneMatch(g -> g.id().equals("ops")));
  }

  private int post(final String path, final String json) throws IOException, InterruptedException {
    final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Authorization", "Bearer " + ADMIN_TOKEN)
        .header("Content-Type", "application/json")
        .POST(BodyPublishers.ofString(json))
        .build();
    final HttpResponse<String> response = raw.send(request, BodyHandlers.ofString());
    return response.statusCode();
  }
}
