package com.codeheadsystems.minitoken.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The opt-in pre-published next key: published before it signs, promoted on rotation. */
class SigningKeyServiceNextKeyTest {

  private static final Duration RETENTION = Duration.ofMinutes(10);

  @Test
  void theNextKeyIsPublishedBeforeItSignsAndPromotedOnRotation() {
    final SigningKeyService keys = service(new MemoryStore(), true);
    final String active = keys.activeKid();
    final String next = keys.nextKid();
    assertNotNull(next);
    assertNotEquals(active, next);
    assertEquals(List.of(active, next), kids(keys), "active and next are both published");
    assertEquals(active, keys.currentSigner().kid(), "the next key does not sign yet");

    final String rotated = keys.rotate();
    assertEquals(next, rotated, "rotation activates the pre-published key");
    assertEquals(next, keys.currentSigner().kid());
    final String newNext = keys.nextKid();
    assertNotNull(newNext);
    assertTrue(kids(keys).containsAll(List.of(active, next, newNext)), "retired, active and next");
    assertEquals(3, kids(keys).size());
  }

  @Test
  void theNextKeySurvivesARestart() {
    final MemoryStore store = new MemoryStore();
    final SigningKeyService first = service(store, true);
    final SigningKeyService reloaded = service(store, true);
    assertEquals(first.activeKid(), reloaded.activeKid());
    assertEquals(first.nextKid(), reloaded.nextKid());
  }

  @Test
  void aSetWrittenWithoutANextKeyGainsOneOnLoad() {
    final MemoryStore store = new MemoryStore();
    final String active = service(store, false).activeKid();
    final SigningKeyService upgraded = service(store, true);
    assertEquals(active, upgraded.activeKid(), "the active key is kept");
    assertNotNull(upgraded.nextKid());
    assertEquals(2, store.document.keys().size(), "the new next key was persisted");
  }

  @Test
  void withoutPrePublicationNothingChanges() {
    final SigningKeyService keys = service(new MemoryStore(), false);
    assertNull(keys.nextKid());
    assertEquals(1, kids(keys).size());
    final String old = keys.activeKid();
    final String rotated = keys.rotate();
    assertNotEquals(old, rotated);
    assertNull(keys.nextKid());
    assertEquals(List.of(old, rotated), kids(keys));
  }

  @Test
  void aNextKeyLeftByAnEarlierRunIsStillPromotedWhenPrePublicationIsOff() {
    final MemoryStore store = new MemoryStore();
    final String next = service(store, true).nextKid();
    final SigningKeyService keys = service(store, false);
    assertEquals(next, keys.rotate(), "an already-published key is used rather than discarded");
    assertNull(keys.nextKid());
  }

  private static SigningKeyService service(final MemoryStore store, final boolean prePublish) {
    return new SigningKeyService(store, SigningAlgorithm.EDDSA, new RandomIds(), Clock.systemUTC(),
        RETENTION, prePublish);
  }

  private static List<String> kids(final SigningKeyService keys) {
    return keys.jwkSet().keys().stream().map(Jwk::keyId).toList();
  }

  private static final class MemoryStore implements DocumentStore<SigningKeys> {
    private SigningKeys document;

    @Override
    public boolean exists() {
      return document != null;
    }

    @Override
    public SigningKeys load() {
      return document;
    }

    @Override
    public void save(final SigningKeys value) {
      document = value;
    }
  }
}
