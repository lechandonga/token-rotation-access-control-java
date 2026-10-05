package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import java.time.Clock;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class TestClockConfig {

    @Bean("systemClock")
    public Clock systemClock() {
        return new MutableClock();
    }
}
