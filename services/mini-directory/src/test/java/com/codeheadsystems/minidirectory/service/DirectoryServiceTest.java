package com.codeheadsystems.minidirectory.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minidirectory.model.Account;
import com.codeheadsystems.minidirectory.model.GrantSpec;
import com.codeheadsystems.minidirectory.model.ResolvedPrincipal;
import com.codeheadsystems.minidirectory.secret.Argon2SecretHasher;
import com.codeheadsystems.minidirectory.secret.Argon2Settings;
import com.codeheadsystems.minidirectory.store.DirectoryDocument;
import com.codeheadsystems.minidirectory.store.JsonStore;
import com.codeheadsystems.minidirectory.util.RandomIds;
import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Decision;
import com.codeheadsystems.minipolicy.GrantBasedPolicyEngine;
import com.codeheadsystems.minipolicy.Resource;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises the directory entirely through the service: CRUD, role/group → grant resolution, the
 * mapping onto a mini-policy decision, no-oracle credential verification, and persistence.
 */
class DirectoryServiceTest {

  private Path file;
  private DirectoryService directory;

  @BeforeEach
  void setUp(@TempDir final Path dir) {
    file = dir.resolve("directory.json");
    directory = newService();
  }

  private DirectoryService newService() {
    // Small Argon2 params keep the test fast; production uses Argon2Settings.defaults().
    return new DirectoryService(
        new JsonStore<>(file, DirectoryDocument.class),
        new Argon2SecretHasher(new Argon2Settings(1024, 1, 1)),
        new RandomIds());
  }

  private static GrantSpec grant(final String action, final String resource) {
    return new GrantSpec(action, resource);
  }

  @Test
  void resolvedHumanMapsCleanlyOntoAMiniPolicyDecision() {
    // A role bundles a grant; a group confers the role; a human is a member of the group.
    directory.createRole("billing-operator", "ops on billing", List.of(grant("ENCRYPT", "billing")));
    directory.createGroup("finance", "the finance team", List.of("billing-operator"), List.of());
    directory.createHuman("alice", "Alice", false, List.of("finance"), List.of(), List.of());

    final ResolvedPrincipal resolved = directory.resolve("alice").orElseThrow();
    assertEquals("alice", resolved.principal().id());
    assertFalse(resolved.principal().admin());

    // The role's grant reached the principal by way of group membership → role expansion.
    final GrantBasedPolicyEngine engine = resolved.toPolicyEngine();
    assertEquals(Decision.ALLOW,
        engine.decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("billing")));
    // Anything not granted is denied.
    assertEquals(Decision.DENY,
        engine.decide(resolved.principal(), Action.of("DECRYPT"), Resource.of("billing")));
    assertEquals(Decision.DENY,
        engine.decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("audit")));
  }

  @Test
  void adminPrincipalIsPermittedEverything() {
    directory.createHuman("root", "Root", true, List.of(), List.of(), List.of());
    final ResolvedPrincipal resolved = directory.resolve("root").orElseThrow();
    assertTrue(resolved.principal().admin());
    final GrantBasedPolicyEngine engine = resolved.toPolicyEngine();
    assertEquals(Decision.ALLOW,
        engine.decide(resolved.principal(), Action.of("anything"), Resource.of("whatever")));
  }

  @Test
  void effectiveGrantsUnionDirectRolesAndGroupsAndDeduplicate() {
    directory.createRole("r-enc", null, List.of(grant("ENCRYPT", "billing")));
    directory.createRole("r-dec", null, List.of(grant("DECRYPT", "billing")));
    // The group confers r-enc AND, redundantly, a direct ENCRYPT/billing grant (to test dedup).
    directory.createGroup("g", null, List.of("r-enc"), List.of(grant("ENCRYPT", "billing")));
    // The account is in the group, directly holds r-dec, and a direct grant on another resource.
    directory.createHuman("svc", null, false, List.of("g"), List.of("r-dec"),
        List.of(grant("GENERATE_DATA_KEY", "audit")));

    final ResolvedPrincipal resolved = directory.resolve("svc").orElseThrow();
    // ENCRYPT/billing appears via both the role and the group's direct grant — counted once.
    assertEquals(3, resolved.grants().size(), "grants must be de-duplicated");

    final GrantBasedPolicyEngine engine = resolved.toPolicyEngine();
    assertEquals(Decision.ALLOW, engine.decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("billing")));
    assertEquals(Decision.ALLOW, engine.decide(resolved.principal(), Action.of("DECRYPT"), Resource.of("billing")));
    assertEquals(Decision.ALLOW, engine.decide(resolved.principal(), Action.of("GENERATE_DATA_KEY"), Resource.of("audit")));
  }

  @Test
  void wildcardGrantPermitsAnyActionOnAResource() {
    directory.createRole("billing-admin", null, List.of(grant("*", "billing")));
    directory.createHuman("op", null, false, List.of(), List.of("billing-admin"), List.of());
    final ResolvedPrincipal resolved = directory.resolve("op").orElseThrow();
    final GrantBasedPolicyEngine engine = resolved.toPolicyEngine();
    assertEquals(Decision.ALLOW, engine.decide(resolved.principal(), Action.of("DECRYPT"), Resource.of("billing")));
    assertEquals(Decision.ALLOW, engine.decide(resolved.principal(), Action.of("RE_ENCRYPT"), Resource.of("billing")));
    assertEquals(Decision.DENY, engine.decide(resolved.principal(), Action.of("ENCRYPT"), Resource.of("audit")));
  }

  @Test
  void serviceAccountSecretVerifiesWithNoOracle() {
    final DirectoryService.Registration registration =
        directory.createServiceAccount("worker", false, List.of(), List.of(), List.of());
    final char[] secret = registration.secret();
    final String id = registration.account().id();

    assertTrue(directory.authenticate(id, secret.clone()).isPresent());
    assertFalse(directory.authenticate(id, "wrong".toCharArray()).isPresent());
    assertFalse(directory.authenticate("svc_unknown", secret.clone()).isPresent());
    // A human has no secret, so it can never authenticate this way.
    directory.createHuman("bob", null, false, List.of(), List.of(), List.of());
    assertFalse(directory.authenticate("bob", secret.clone()).isPresent());
  }

  @Test
  void disabledServiceAccountCannotAuthenticate() {
    final DirectoryService.Registration registration =
        directory.createServiceAccount("worker", false, List.of(), List.of(), List.of());
    final String id = registration.account().id();
    directory.assign(id, false, false, List.of(), List.of(), List.of());
    assertFalse(directory.authenticate(id, registration.secret().clone()).isPresent());
  }

  @Test
  void assignmentReplacesAuthorizationAndReResolves() {
    directory.createRole("r", null, List.of(grant("DECRYPT", "billing")));
    directory.createHuman("u", null, false, List.of(), List.of(), List.of());
    assertTrue(directory.resolve("u").orElseThrow().grants().isEmpty());

    final Optional<Account> updated = directory.assign("u", true, true, List.of(), List.of("r"), List.of());
    assertTrue(updated.isPresent());
    assertTrue(updated.get().admin());
    assertEquals(1, directory.resolve("u").orElseThrow().grants().size());
  }

  @Test
  void duplicateIdsAndDanglingReferencesAreRejected() {
    directory.createRole("dup", null, List.of());
    assertThrows(IllegalStateException.class, () -> directory.createRole("dup", null, List.of()));

    directory.createHuman("carol", null, false, List.of(), List.of(), List.of());
    assertThrows(IllegalStateException.class,
        () -> directory.createHuman("carol", null, false, List.of(), List.of(), List.of()));

    // Referencing a role/group that does not exist is a bad request, not a silent no-op.
    assertThrows(IllegalArgumentException.class,
        () -> directory.createHuman("dave", null, false, List.of("nope"), List.of(), List.of()));
    assertThrows(IllegalArgumentException.class,
        () -> directory.createHuman("erin", null, false, List.of(), List.of("nope"), List.of()));
    assertThrows(IllegalArgumentException.class,
        () -> directory.createGroup("grp", null, List.of("nope"), List.of()));
  }

  @Test
  void stateSurvivesAReload() {
    directory.createRole("r", "desc", List.of(grant("ENCRYPT", "billing")));
    directory.createGroup("g", null, List.of("r"), List.of());
    directory.createHuman("alice", "Alice", false, List.of("g"), List.of(), List.of());
    final DirectoryService.Registration reg =
        directory.createServiceAccount("svc", false, List.of(), List.of("r"), List.of());

    // A fresh service over the same file must see everything, including the hashed secret.
    final DirectoryService reloaded = newService();
    assertTrue(reloaded.getRole("r").isPresent());
    assertTrue(reloaded.getGroup("g").isPresent());
    assertEquals(1, reloaded.resolve("alice").orElseThrow().grants().size());
    assertTrue(reloaded.authenticate(reg.account().id(), reg.secret().clone()).isPresent(),
        "the persisted service-account secret hash must still verify after reload");
  }

  @Test
  void deletingARoleStillReferencedDoesNotBreakResolution() {
    directory.createRole("r", null, List.of(grant("ENCRYPT", "billing")));
    directory.createHuman("u", null, false, List.of(), List.of("r"), List.of());
    assertTrue(directory.deleteRole("r"));
    // The dangling reference is tolerated: resolution simply yields no grant for the missing role.
    final ResolvedPrincipal resolved = directory.resolve("u").orElseThrow();
    assertTrue(resolved.grants().isEmpty());
  }
}
