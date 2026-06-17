package com.codeheadsystems.minioidc.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A {@link Clock} whose instant can be advanced, for deterministic expiry/replay tests. */
public final class MutableClock extends Clock {

  private Instant now;
  private final ZoneId zone;

  public MutableClock(final Instant start) {
    this(start, ZoneOffset.UTC);
  }

  private MutableClock(final Instant now, final ZoneId zone) {
    this.now = now;
    this.zone = zone;
  }

  public void advance(final Duration duration) {
    now = now.plus(duration);
  }

  @Override
  public ZoneId getZone() {
    return zone;
  }

  @Override
  public Clock withZone(final ZoneId zone) {
    return new MutableClock(now, zone);
  }

  @Override
  public Instant instant() {
    return now;
  }
}
