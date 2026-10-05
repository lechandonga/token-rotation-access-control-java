package com.github.lechandonga.tokenrotationaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 鉴权与令牌生命周期相关配置项。
 */
@ConfigurationProperties(prefix = "app.auth")
public class AuthProperties {

    /** 访问凭证有效期。 */
    private Duration accessTokenTtl = Duration.ofMinutes(30);

    /** 刷新凭证有效期（相对签发或上次轮换时间）。 */
    private Duration refreshTokenTtl = Duration.ofDays(7);

    /** 签名密钥轮换后的旧密钥校验宽限期。 */
    private Duration keyGracePeriod = Duration.ofHours(24);

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }

    public void setRefreshTokenTtl(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public Duration getKeyGracePeriod() {
        return keyGracePeriod;
    }

    public void setKeyGracePeriod(Duration keyGracePeriod) {
        this.keyGracePeriod = keyGracePeriod;
    }
}
