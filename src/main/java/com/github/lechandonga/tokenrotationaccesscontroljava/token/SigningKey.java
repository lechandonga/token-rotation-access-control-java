package com.github.lechandonga.tokenrotationaccesscontroljava.token;

import java.time.Instant;

/**
 * 一个签名密钥版本。状态机：ACTIVE -> RETIRED ->（宽限期结束后）EXPIRED；
 * 任意状态都可被 REVOKED，REVOKED 与 EXPIRED 为终态。
 */
public record SigningKey(
        String keyId,
        byte[] secret,
        State state,
        Instant activatedAt,
        Instant retiredAt,
        Instant graceDeadline,
        long version) {

    public enum State {
        ACTIVE,
        RETIRED,
        EXPIRED,
        REVOKED
    }

    /** 该密钥此刻是否可用于校验旧凭证（未吊销且处于宽限期内）。 */
    public boolean canVerify(Instant now) {
        return switch (state) {
            case ACTIVE -> true;
            case RETIRED -> graceDeadline != null && now.isBefore(graceDeadline);
            case EXPIRED, REVOKED -> false;
        };
    }

    public SigningKey retire(Instant now, Instant graceDeadline) {
        return new SigningKey(keyId, secret, State.RETIRED, activatedAt, now, graceDeadline, version + 1);
    }

    public SigningKey expire() {
        return new SigningKey(keyId, secret, State.EXPIRED, activatedAt, retiredAt, graceDeadline, version + 1);
    }

    public SigningKey revoke() {
        return new SigningKey(keyId, secret, State.REVOKED, activatedAt, retiredAt, graceDeadline, version + 1);
    }
}
