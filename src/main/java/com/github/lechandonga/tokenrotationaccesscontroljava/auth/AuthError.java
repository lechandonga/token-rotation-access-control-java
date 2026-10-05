package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import org.springframework.http.HttpStatus;

/**
 * 可区分的鉴权/令牌失败原因。每一类错误都有独立错误码，便于调用方与日志识别。
 */
public enum AuthError {
    MISSING_CREDENTIAL("missing_credential", HttpStatus.UNAUTHORIZED),
    MALFORMED_CREDENTIAL("malformed_credential", HttpStatus.UNAUTHORIZED),
    EXPIRED_TOKEN("expired_token", HttpStatus.UNAUTHORIZED),
    REVOKED_TOKEN("revoked_token", HttpStatus.UNAUTHORIZED),
    INVALID_SIGNATURE("invalid_signature", HttpStatus.UNAUTHORIZED),
    UNKNOWN_KEY("unknown_key", HttpStatus.UNAUTHORIZED),
    TOKEN_FAMILY_REVOKED("token_family_revoked", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REUSED("refresh_token_reused", HttpStatus.UNAUTHORIZED),
    INSUFFICIENT_SCOPE("insufficient_scope", HttpStatus.FORBIDDEN),
    INVALID_SUBJECT("invalid_subject", HttpStatus.UNAUTHORIZED);

    private final String code;
    private final HttpStatus status;

    AuthError(String code, HttpStatus status) {
        this.code = code;
        this.status = status;
    }

    public String code() {
        return code;
    }

    public HttpStatus status() {
        return status;
    }
}
