package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.github.lechandonga.tokenrotationaccesscontroljava.config.AuthProperties;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/**
 * 刷新凭证与令牌族的内存状态管理。
 *
 * <p>一个令牌族（family）从登录开始，每次刷新轮换出新一代刷新凭证。
 * 只有"当前最新一代"刷新凭证可以成功使用一次；旧凭证再次出现即判定为重用，
 * 整个令牌族立即吊销，族内此后所有凭证（含已签发的访问凭证）全部失效。
 *
 * <p>所有读取与轮换都在同一监视器上原子完成，并发刷新下至多一个请求成功，
 * 不会出现两个请求同时成功，也不会出现状态互相覆盖。
 */
@Component
public class RefreshTokenFamilyService {

    /** 一代刷新凭证的运行时状态。 */
    private record RefreshEntry(String jti, String familyId, String subject, long generation,
                                long issuedAt, long expiresAt) {
    }

    /** 令牌族状态。 */
    private static final class Family {
        private final String subject;
        private final String currentJti;
        private final long generation;
        private final long currentExpiresAt;
        private final boolean revoked;

        private Family(String subject, String currentJti, long generation, long currentExpiresAt,
                       boolean revoked) {
            this.subject = subject;
            this.currentJti = currentJti;
            this.generation = generation;
            this.currentExpiresAt = currentExpiresAt;
            this.revoked = revoked;
        }
    }

    /** 成功轮换的结果。 */
    public record RotationResult(String subject, String newRefreshToken, String familyId) {
    }

    /** 新建令牌族的结果。 */
    public record FamilyStart(String familyId, String refreshToken) {
    }

    private record State(Map<String, Family> families, Map<String, RefreshEntry> jtiIndex) {
    }

    private final SecureRandom secureRandom = new SecureRandom();
    private final TimeSource timeSource;
    private final AuthProperties properties;

    private State state;

    public RefreshTokenFamilyService(TimeSource timeSource, AuthProperties properties) {
        this.timeSource = timeSource;
        this.properties = properties;
        this.state = new State(new java.util.HashMap<>(), new java.util.HashMap<>());
    }

    /** 登录时创建令牌族并签发第一代刷新凭证。 */
    public synchronized FamilyStart startFamily(String subject) {
        long now = timeSource.epochMillis();
        String familyId = newTokenId("fam");
        String jti = newTokenId("rt");
        long exp = now + properties.getRefreshTokenTtl().toMillis();
        Family family = new Family(subject, jti, 0, exp, false);
        Map<String, Family> families = new java.util.HashMap<>(state.families);
        Map<String, RefreshEntry> index = new java.util.HashMap<>(state.jtiIndex);
        families.put(familyId, family);
        index.put(jti, new RefreshEntry(jti, familyId, subject, 0, now, exp));
        state = new State(families, index);
        return new FamilyStart(familyId, jti);
    }

    /**
     * 原子执行刷新轮换。
     *
     * <p>失败时按原因抛出：
     * <ul>
     *   <li>{@link AuthErrorCode#REFRESH_NOT_FOUND} 凭证不存在</li>
     *   <li>{@link AuthErrorCode#REFRESH_FAMILY_REVOKED} 令牌族此前已被吊销</li>
     *   <li>{@link AuthErrorCode#REFRESH_REUSED} 旧凭证被重用（本次操作吊销整族）</li>
     *   <li>{@link AuthErrorCode#REFRESH_EXPIRED} 凭证已过期</li>
     * </ul>
     */
    public synchronized RotationResult rotate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(AuthErrorCode.REFRESH_NOT_FOUND);
        }
        long now = timeSource.epochMillis();
        RefreshEntry entry = state.jtiIndex.get(refreshToken);
        if (entry == null) {
            throw new AuthException(AuthErrorCode.REFRESH_NOT_FOUND);
        }
        Family family = state.families.get(entry.familyId());
        if (family == null || family.revoked) {
            throw new AuthException(AuthErrorCode.REFRESH_FAMILY_REVOKED);
        }
        // 只有族内当前最新一代凭证可成功使用；出现任何旧凭证都视为重用。
        if (!family.currentJti.equals(entry.jti())) {
            revokeFamilyLocked(entry.familyId());
            throw new AuthException(AuthErrorCode.REFRESH_REUSED);
        }
        if (now >= entry.expiresAt() || now >= family.currentExpiresAt) {
            throw new AuthException(AuthErrorCode.REFRESH_EXPIRED);
        }

        String newJti = newTokenId("rt");
        long newExp = now + properties.getRefreshTokenTtl().toMillis();
        long newGeneration = family.generation + 1;
        Family updated = new Family(family.subject, newJti, newGeneration, newExp, false);
        Map<String, Family> families = new java.util.HashMap<>(state.families);
        Map<String, RefreshEntry> index = new java.util.HashMap<>(state.jtiIndex);
        families.put(entry.familyId(), updated);
        // 旧 jti 的索引记录保留（标记为已轮换的历史凭证），用于识别重用。
        index.put(newJti, new RefreshEntry(newJti, entry.familyId(), family.subject, newGeneration, now, newExp));
        state = new State(families, index);
        return new RotationResult(family.subject, newJti, entry.familyId());
    }

    /** 查询令牌族是否已吊销（访问凭证校验使用）。 */
    public boolean isFamilyRevoked(String familyId) {
        Family family = state.families.get(familyId);
        return family == null || family.revoked;
    }

    /** 主动吊销整个令牌族（登出等场景）。 */
    public synchronized void revokeFamily(String familyId) {
        if (!state.families.containsKey(familyId)) {
            throw new AuthException(AuthErrorCode.REFRESH_NOT_FOUND);
        }
        revokeFamilyLocked(familyId);
    }

    private void revokeFamilyLocked(String familyId) {
        Family family = state.families.get(familyId);
        if (family == null || family.revoked) {
            return;
        }
        Map<String, Family> families = new java.util.HashMap<>(state.families);
        families.put(familyId, new Family(family.subject, family.currentJti, family.generation,
                family.currentExpiresAt, true));
        state = new State(families, state.jtiIndex);
    }

    private String newTokenId(String prefix) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return prefix + "_" + HexFormat.of().formatHex(bytes);
    }
}
