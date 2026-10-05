package com.github.lechandonga.tokenrotationaccesscontroljava.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 令牌与签名密钥相关的可配置项，前缀 {@code token-rotation.security}。
 */
@ConfigurationProperties(prefix = "token-rotation.security")
public record SecurityProps(
        Duration accessTtl,
        Duration refreshTtl,
        Duration keyGracePeriod) {

    public static final Duration DEFAULT_ACCESS_TTL = Duration.ofMinutes(10);
    public static final Duration DEFAULT_REFRESH_TTL = Duration.ofHours(12);
    public static final Duration DEFAULT_KEY_GRACE_PERIOD = Duration.ofDays(7);

    public SecurityProps {
        accessTtl = accessTtl != null ? accessTtl : DEFAULT_ACCESS_TTL;
        refreshTtl = refreshTtl != null ? refreshTtl : DEFAULT_REFRESH_TTL;
        keyGracePeriod = keyGracePeriod != null ? keyGracePeriod : DEFAULT_KEY_GRACE_PERIOD;
    }
}
