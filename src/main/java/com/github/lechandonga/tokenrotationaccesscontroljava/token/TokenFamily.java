package com.github.lechandonga.tokenrotationaccesscontroljava.token;

/**
 * 刷新令牌族的生命周期状态。
 * ACTIVE: 族内当前刷新凭证可用；REVOKED: 被显式吊销；COMPROMISED: 检测到刷新凭证重用，整族失效。
 */
public record TokenFamily(
        String familyId,
        String subject,
        State state,
        String currentRefreshTokenId,
        long createdAtEpochMilli,
        long updatedAtEpochMilli,
        long version) {

    public enum State {
        ACTIVE,
        REVOKED,
        COMPROMISED
    }

    public TokenFamily rotate(String newRefreshTokenId, long now) {
        return new TokenFamily(familyId, subject, State.ACTIVE, newRefreshTokenId,
                createdAtEpochMilli, now, version + 1);
    }

    public TokenFamily mark(State newState, long now) {
        return new TokenFamily(familyId, subject, newState, currentRefreshTokenId,
                createdAtEpochMilli, now, version + 1);
    }
}
