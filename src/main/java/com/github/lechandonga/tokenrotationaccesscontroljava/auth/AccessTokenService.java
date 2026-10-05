package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.github.lechandonga.tokenrotationaccesscontroljava.config.AuthProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 访问凭证服务：签发与校验 HMAC 签名的紧凑令牌。
 *
 * <p>令牌格式为 {@code base64url(header).base64url(payload).base64url(signature)}，
 * header 中带 {@code kid} 以标识签发所用密钥，支持密钥轮换后的新旧并存校验。
 */
@Component
public class AccessTokenService {

    /** 校验通过后的访问凭证内容。 */
    public record AccessToken(String subject, String familyId, java.util.Set<String> scopes,
                              long issuedAt, long expiresAt, String keyId) {
    }

    private record Header(String alg, String kid) {
    }

    private record Payload(String sub, String fam, java.util.Set<String> scope, long iat, long exp) {
    }

    private final SigningKeyService signingKeyService;
    private final RefreshTokenFamilyService familyService;
    private final TimeSource timeSource;
    private final AuthProperties properties;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public AccessTokenService(SigningKeyService signingKeyService,
                              RefreshTokenFamilyService familyService,
                              TimeSource timeSource,
                              AuthProperties properties) {
        this.signingKeyService = signingKeyService;
        this.familyService = familyService;
        this.timeSource = timeSource;
        this.properties = properties;
    }

    public String issue(Principal principal, String familyId) {
        SigningKeyService.KeyInfo key = signingKeyService.currentSigningKey();
        long now = timeSource.epochMillis();
        long exp = now + properties.getAccessTokenTtl().toMillis();
        Header header = new Header("HS256", key.keyId());
        Payload payload = new Payload(principal.subjectId(), familyId, principal.scopes(), now, exp);
        String headerPart = encoder.encodeToString(JsonCodec.toJson(header).getBytes(StandardCharsets.UTF_8));
        String payloadPart = encoder.encodeToString(JsonCodec.toJson(payload).getBytes(StandardCharsets.UTF_8));
        String signingInput = headerPart + "." + payloadPart;
        SecretKey secretKey = signingKeyService.findVerifyingKey(key.keyId());
        String signaturePart = encoder.encodeToString(hmac(secretKey, signingInput));
        return signingInput + "." + signaturePart;
    }

    /**
     * 完整校验访问凭证，按失败类型抛出不同 {@link AuthErrorCode}，绝不静默放行。
     */
    public AccessToken verify(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException(AuthErrorCode.MISSING_CREDENTIAL);
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            throw new AuthException(AuthErrorCode.MALFORMED_CREDENTIAL);
        }
        Header header;
        Payload payload;
        try {
            header = JsonCodec.fromJson(new String(decoder.decode(parts[0]), StandardCharsets.UTF_8), Header.class);
            payload = JsonCodec.fromJson(new String(decoder.decode(parts[1]), StandardCharsets.UTF_8), Payload.class);
        } catch (IllegalArgumentException | JsonCodec.JsonException e) {
            throw new AuthException(AuthErrorCode.MALFORMED_CREDENTIAL);
        }
        if (header == null || header.kid() == null || !"HS256".equals(header.alg())
                || payload == null || payload.sub() == null || payload.fam() == null) {
            throw new AuthException(AuthErrorCode.MALFORMED_CREDENTIAL);
        }
        SecretKey secretKey = signingKeyService.findVerifyingKey(header.kid());
        if (secretKey == null) {
            // 可能是密钥未知（含被移除）、被吊销或宽限期结束，统一在密钥层判定。
            throw new AuthException(AuthErrorCode.UNKNOWN_SIGNING_KEY);
        }
        byte[] expected = hmac(secretKey, parts[0] + "." + parts[1]);
        if (!constantTimeEquals(expected, decoder.decode(parts[2]))) {
            throw new AuthException(AuthErrorCode.INVALID_SIGNATURE);
        }
        if (timeSource.epochMillis() >= payload.exp()) {
            throw new AuthException(AuthErrorCode.TOKEN_EXPIRED);
        }
        if (familyService.isFamilyRevoked(payload.fam())) {
            throw new AuthException(AuthErrorCode.TOKEN_REVOKED);
        }
        return new AccessToken(payload.sub(), payload.fam(),
                payload.scope() == null ? java.util.Set.of() : payload.scope(),
                payload.iat(), payload.exp(), header.kid());
    }

    private static byte[] hmac(SecretKey key, String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }
}
