package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minitoken.jwks.JwkSet;

/**
 * Supplies the OP's published signing keys for offline bearer-token verification. An SPI so the
 * production path ({@link HttpJwksProvider}, fetching and caching mini-oidc's {@code /jwks.json})
 * and tests (a fixed in-memory set) are interchangeable.
 */
@FunctionalInterface
public interface JwksProvider {

  /** @return the current JWK Set (implementations may cache). */
  JwkSet get();
}
