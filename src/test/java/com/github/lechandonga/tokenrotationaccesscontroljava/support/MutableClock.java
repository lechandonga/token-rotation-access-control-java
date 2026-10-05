package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 可自由拨快的时钟：过期/宽限期用例无需真实等待。 */
public class MutableClock extends Clock {

    private volatile Instant instant = Instant.parse("2026-10-05T00:00:00Z");
    private final ZoneId zone = ZoneOffset.UTC;

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Instant instant() {
        return instant;
    }

    public void reset() {
        instant = Instant.parse("2026-10-05T00:00:00Z");
    }

    public void advance(Duration duration) {
        instant = instant.plus(duration);
    }
}
