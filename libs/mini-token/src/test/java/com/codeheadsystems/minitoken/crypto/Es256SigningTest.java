package com.codeheadsystems.minitoken.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.token.Base64Url;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** ES256 alongside Ed25519: key encoding, raw R||S signatures, JWKs, and the per-algorithm key set. */
class Es256SigningTest {

  @Test
  void es256SignatureIsRawRAndSAndVerifiesOnlyAsEs256() {
    final KeyPair pair = SigningAlgorithm.ES256.generate();
    final String token = Jws.sign(JwsHeader.forKid(SigningAlgorithm.ES256, "k1"),
        Map.of("sub", "billing"), pair.getPrivate());
    final Jws.Parts parts = Jws.split(token);

    assertEquals("ES256", Jws.parseHeader(parts).algorithm());
    assertEquals(64, Base64Url.decode(parts.signature()).length, "JWS ES256 is R||S, not DER");
    assertTrue(Jws.verifySignature(parts, pair.getPublic(), SigningAlgorithm.ES256));
    // The historical two-argument verify is pinned to Ed25519 and must not accept an EC key.
    assertFalse(Jws.verifySignature(parts, pair.getPublic()));
  }

  @Test
  void eddsaSigningIsUnchanged() {
    final KeyPair pair = SigningAlgorithm.EDDSA.generate();
    final String token = Jws.sign(JwsHeader.forKid("k1"), Map.of("sub", "x"), pair.getPrivate());
    final Jws.Parts parts = Jws.split(token);
    assertEquals("EdDSA", Jws.parseHeader(parts).algorithm());
    assertTrue(Jws.verifySignature(parts, pair.getPublic()));
  }

  @Test
  void ecJwkPublishesFixedWidthCoordinatesAndRoundTrips() {
    final KeyPair pair = SigningAlgorithm.ES256.generate();
    final Jwk jwk = Jwk.forEcP256("k1", pair.getPublic());
    assertEquals("EC", jwk.keyType());
    assertEquals("P-256", jwk.curve());
    assertEquals("ES256", jwk.algorithm());
    assertEquals("sig", jwk.use());
    assertEquals(32, Base64Url.decode(jwk.publicKey()).length);
    assertEquals(32, Base64Url.decode(jwk.y()).length);
    assertArrayEquals(pair.getPublic().getEncoded(), jwk.toPublicKey().getEncoded());
    assertNull(Jwk.forEd25519("k2", SigningAlgorithm.EDDSA.generate().getPublic()).y());
  }

  @Test
  void coordinatesArePaddedOrTrimmedToThirtyTwoBytes() {
    assertEquals(32, EcP256Keys.coordinate(BigInteger.ONE).length);
    final BigInteger highBit = BigInteger.ONE.shiftLeft(255); // toByteArray() gives 33 bytes
    assertEquals(32, EcP256Keys.coordinate(highBit).length);
    assertEquals(highBit, new BigInteger(1, EcP256Keys.coordinate(highBit)));
    assertThrows(IllegalStateException.class, () -> EcP256Keys.coordinate(BigInteger.ONE.shiftLeft(300)));
  }

  @Test
  void algorithmNamesParseCaseInsensitively() {
    assertEquals(SigningAlgorithm.ES256, SigningAlgorithm.fromJwsName("es256"));
    assertEquals(SigningAlgorithm.EDDSA, SigningAlgorithm.fromJwsName("EdDSA"));
    assertThrows(IllegalArgumentException.class, () -> SigningAlgorithm.fromJwsName("HS256"));
  }

  @Test
  void es256KeySetRotatesAndPersistsLikeTheEd25519One() {
    final MemoryStore store = new MemoryStore();
    final SigningKeyService keys = new SigningKeyService(
        store, SigningAlgorithm.ES256, new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(10));
    assertEquals(SigningAlgorithm.ES256, keys.currentSigner().algorithm());
    final String first = keys.activeKid();
    final String second = keys.rotate();
    assertNotEquals(first, second);
    assertEquals(2, keys.jwkSet().keys().size(), "the retired key stays published");
    assertTrue(keys.jwkSet().keys().stream().allMatch(k -> "EC".equals(k.keyType())));

    // Reloaded from the store, the key set is read back as ES256.
    final SigningKeyService reloaded = new SigningKeyService(
        store, SigningAlgorithm.ES256, new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(10));
    assertEquals(second, reloaded.activeKid());
    assertEquals("EC", reloaded.currentSigner().privateKey().getAlgorithm());
  }

  /** A trivial in-memory DocumentStore. */
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
