package com.github.lechandonga.tokenrotationaccesscontroljava.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthError;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * 自包含紧凑令牌编解码：{@code base64url(payload).base64url(hmac-sha256(payload))}。
 * 不依赖任何外部令牌库；密钥标识 kid 放在 payload 中，签名后不可篡改。
 */
@Component
public class TokenCodec {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private final ObjectMapper objectMapper;

    public TokenCodec(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String encode(Object claims, byte[] secret) {
        try {
            byte[] payload = objectMapper.writeValueAsBytes(claims);
            String payloadPart = URL_ENCODER.encodeToString(payload);
            String signaturePart = URL_ENCODER.encodeToString(hmac(payloadPart, secret));
            return payloadPart + "." + signaturePart;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("令牌序列化失败", e);
        }
    }

    /**
     * 解码并验签。先验结构再验签：结构问题归 MALFORMED_CREDENTIAL，
     * 签名不匹配归 INVALID_SIGNATURE。
     */
    public <T> T decode(String token, byte[] secret, Class<T> claimsType) {
        int dot = token == null ? -1 : token.lastIndexOf('.');
        if (dot <= 0 || dot == token.length() - 1 || token.indexOf('.') != dot) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌结构错误: 应为 payload.signature 两段");
        }
        String payloadPart = token.substring(0, dot);
        String signaturePart = token.substring(dot + 1);

        byte[] expected = hmac(payloadPart, secret);
        byte[] provided;
        try {
            provided = URL_DECODER.decode(signaturePart);
        } catch (IllegalArgumentException e) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌签名段 Base64URL 解码失败");
        }
        if (!constantTimeEquals(expected, provided)) {
            throw new AuthException(AuthError.INVALID_SIGNATURE, "令牌签名校验失败");
        }

        try {
            byte[] payload = URL_DECODER.decode(payloadPart);
            return objectMapper.readValue(payload, claimsType);
        } catch (IllegalArgumentException e) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌载荷段 Base64URL 解码失败");
        } catch (java.io.IOException e) {
            throw new AuthException(AuthError.MALFORMED_CREDENTIAL, "令牌载荷无法解析");
        }
    }

    private byte[] hmac(String payloadPart, byte[] secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(payloadPart.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
