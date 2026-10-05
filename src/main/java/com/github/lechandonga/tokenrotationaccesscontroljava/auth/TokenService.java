package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.github.lechandonga.tokenrotationaccesscontroljava.config.SecurityProps;
import com.github.lechandonga.tokenrotationaccesscontroljava.subject.Subject;
import com.github.lechandonga.tokenrotationaccesscontroljava.subject.SubjectDirectory;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.AccessToken;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.IssuedPair;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.RefreshToken;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.SigningKey;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.TokenCodec;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.TokenFamily;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.TokenStore;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 令牌生命周期总入口：签发、访问凭证校验、刷新轮换与重用检测、显式吊销。
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private final Clock clock;
    private final SecurityProps props;
    private final SubjectDirectory subjectDirectory;
    private final KeyManagerLookup keyManager;
    private final TokenCodec codec;
    private final TokenStore store;

    public TokenService(Clock clock, SecurityProps props, SubjectDirectory subjectDirectory,
                        KeyManagerLookup keyManager, TokenCodec codec, TokenStore store) {
        this.clock = clock;
        this.props = props;
        this.subjectDirectory = subjectDirectory;
        this.keyManager = keyManager;
        this.codec = codec;
        this.store = store;
    }

    /** 模拟登录：主体标识 -> 首个访问/刷新凭证对，并建立令牌族。 */
    public IssuedPair issue(String subjectId) {
        Subject subject = subjectDirectory.require(subjectId);
        long now = Instant.now(clock).toEpochMilli();
        String familyId = "fam-" + UUID.randomUUID();
        TokenFamily family = new TokenFamily(familyId, subject.subjectId(), TokenFamily.State.ACTIVE,
                null, now, now, 0);
        store.create(family);
        return mintPair(family, subject.scopes(), now);
    }

    /**
     * 刷新轮换。整个判定与轮换在族锁内完成：
     * <ol>
     *   <li>验签（旧密钥宽限期内仍可校验，但新凭证一律用当前密钥签发）；</li>
     *   <li>族已 COMPROMISED/REVOKED -> 稳定拒绝；</li>
     *   <li>提交的刷新凭证 jti 不是族内当前凭证 -> 判定为重放，整族标记 COMPROMISED；</li>
     *   <li>过期 -> expired_token（不推进族状态，旧凭证重放仍会被识别）；</li>
     *   <li>成功则原子推进族的 currentRefreshTokenId，旧凭证即刻失效。</li>
     * </ol>
     */
    public IssuedPair rotate(String refreshTokenValue) {
        RefreshToken presented = verifyRefreshSignatureOnly(refreshTokenValue);
        synchronized (store.lockOf(presented.familyId())) {
            TokenFamily family = store.require(presented.familyId());
            long now = Instant.now(clock).toEpochMilli();

            if (family.state() == TokenFamily.State.COMPROMISED) {
                throw new AuthException(AuthError.REFRESH_TOKEN_REUSED,
                        "刷新凭证所属令牌族已因重用被整体吊销: " + family.familyId());
            }
            if (family.state() == TokenFamily.State.REVOKED) {
                throw new AuthException(AuthError.REVOKED_TOKEN,
                        "刷新凭证所属令牌族已被吊销: " + family.familyId());
            }

            if (!presented.tokenId().equals(family.currentRefreshTokenId())) {
                TokenFamily compromised = family.mark(TokenFamily.State.COMPROMISED, now);
                store.save(compromised);
                log.warn("检测到刷新凭证重用 family={} presented={} expected={}，整族吊销",
                        family.familyId(), presented.tokenId(), family.currentRefreshTokenId());
                throw new AuthException(AuthError.REFRESH_TOKEN_REUSED,
                        "刷新凭证已被使用过，令牌族已整体吊销: " + family.familyId());
            }

            if (presented.expiredAt(now)) {
                throw new AuthException(AuthError.EXPIRED_TOKEN,
                        "刷新凭证已过期: " + presented.tokenId());
            }

            Subject subject = subjectDirectory.require(family.subject());
            return mintPair(family, subject.scopes(), now);
        }
    }

    public AccessToken verifyAccessToken(String tokenValue) {
        AccessToken token = decodeWithKeyLookup(tokenValue, AccessToken.class);
        long now = Instant.now(clock).toEpochMilli();
        if (token.expiredAt(now)) {
            throw new AuthException(AuthError.EXPIRED_TOKEN, "访问凭证已过期: " + token.tokenId());
        }
        TokenFamily family = lookupFamilyQuietly(token.familyId());
        if (family != null && family.state() == TokenFamily.State.COMPROMISED) {
            throw new AuthException(AuthError.TOKEN_FAMILY_REVOKED,
                    "令牌族已因刷新凭证重用被整体吊销: " + token.familyId());
        }
        if (family != null && family.state() == TokenFamily.State.REVOKED) {
            throw new AuthException(AuthError.REVOKED_TOKEN,
                    "令牌族已被吊销: " + token.familyId());
        }
        return token;
    }

    public void revokeFamily(String familyId) {
        store.revokeFamily(familyId, TokenFamily.State.REVOKED);
    }

    private IssuedPair mintPair(TokenFamily family, List<String> scopes, long now) {
        SigningKey signingKey = keyManager.get().currentSigningKey();
        AccessToken access = new AccessToken(
                "at-" + UUID.randomUUID(), family.subject(), List.copyOf(scopes), family.familyId(),
                signingKey.keyId(), now, now + props.accessTtl().toMillis());
        RefreshToken refresh = new RefreshToken(
                "rt-" + UUID.randomUUID(), family.subject(), family.familyId(), signingKey.keyId(),
                now, now + props.refreshTtl().toMillis());

        TokenFamily advanced = family.rotate(refresh.tokenId(), now);
        store.save(advanced);

        String accessValue = codec.encode(access, signingKey.secret());
        String refreshValue = codec.encode(refresh, signingKey.secret());
        return new IssuedPair(accessValue, refreshValue, access, refresh);
    }

    private RefreshToken verifyRefreshSignatureOnly(String tokenValue) {
        return decodeWithKeyLookup(tokenValue, RefreshToken.class);
    }

    private <T> T decodeWithKeyLookup(String tokenValue, Class<T> type) {
        String kid = peekKeyId(tokenValue);
        SigningKey key = keyManager.get().keyForVerification(kid);
        return codec.decode(tokenValue, key.secret(), type);
    }

    /**
     * 只读取载荷中的 kid 以定位密钥；载荷经签名保护，kid 被篡改会在验签时失败。
     * 结构无法解析统一归 MALFORMED_CREDENTIAL。
     */
    private String peekKeyId(String tokenValue) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "凭证为空");
        }
        int dot = tokenValue.indexOf('.');
        if (dot <= 0) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌结构错误: 缺少签名段");
        }
        try {
            byte[] payload = java.util.Base64.getUrlDecoder().decode(tokenValue.substring(0, dot));
            com.fasterxml.jackson.databind.JsonNode node =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(payload);
            if (node == null || !node.hasNonNull("keyId")) {
                throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌缺少密钥标识 kid");
            }
            String kid = node.get("keyId").asText();
            if (kid == null || kid.isBlank()) {
                throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌缺少密钥标识 kid");
            }
            return kid;
        } catch (IllegalArgumentException e) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌载荷段 Base64URL 解码失败");
        } catch (java.io.IOException e) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌结构损坏，无法读取密钥标识");
        }
    }

    private TokenFamily lookupFamilyQuietly(String familyId) {
        try {
            return store.require(familyId);
        } catch (AuthException e) {
            return null;
        }
    }

    /** KeyManager 与本服务存在相互引用的潜在循环，用函数式查找解耦。 */
    @FunctionalInterface
    public interface KeyManagerLookup {
        com.github.lechandonga.tokenrotationaccesscontroljava.token.KeyManager get();
    }
}
