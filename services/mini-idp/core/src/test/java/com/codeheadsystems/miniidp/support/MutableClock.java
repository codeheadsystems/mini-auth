package com.codeheadsystems.miniidp.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * A {@link Clock} whose instant can be set and advanced, for deterministic time-based tests
 * (token expiry, not-before, key-retirement pruning).
 */
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

  /** Advance the clock by the given duration. */
  public void advance(final Duration duration) {
    now = now.plus(duration);
  }

  /** Set the clock to an absolute instant. */
  public void set(final Instant instant) {
    now = instant;
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
