package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.TimeSource;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * 测试专用配置：用可控时间源覆盖系统时间源。
 */
@TestConfiguration
public class TestAuthConfiguration {

    @Bean
    @Primary
    public TimeSource controllableTimeSource() {
        return new ControllableTimeSource();
    }
}
