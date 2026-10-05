package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import org.springframework.http.HttpStatus;

/**
 * 可区分的鉴权拒绝原因。每一种失败都有独立错误码，不做笼统合并。
 */
public enum AuthErrorCode {

    MISSING_CREDENTIAL(HttpStatus.UNAUTHORIZED, "缺少访问凭证"),
    MALFORMED_CREDENTIAL(HttpStatus.UNAUTHORIZED, "访问凭证格式错误"),
    UNSUPPORTED_CREDENTIAL(HttpStatus.UNAUTHORIZED, "不支持的认证方式"),
    UNKNOWN_SIGNING_KEY(HttpStatus.UNAUTHORIZED, "签名密钥未知或已彻底过期"),
    INVALID_SIGNATURE(HttpStatus.UNAUTHORIZED, "签名校验失败"),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "凭证已过期"),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED, "凭证已吊销"),
    INSUFFICIENT_SCOPE(HttpStatus.FORBIDDEN, "权限范围不足"),
    REFRESH_NOT_FOUND(HttpStatus.UNAUTHORIZED, "刷新凭证不存在"),
    REFRESH_EXPIRED(HttpStatus.UNAUTHORIZED, "刷新凭证已过期"),
    REFRESH_REUSED(HttpStatus.UNAUTHORIZED, "刷新凭证被重用，整个令牌族已吊销"),
    REFRESH_FAMILY_REVOKED(HttpStatus.UNAUTHORIZED, "令牌族已被吊销"),
    UNKNOWN_SUBJECT(HttpStatus.UNAUTHORIZED, "主体不存在"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "请求参数错误"),
    KEY_NOT_FOUND(HttpStatus.NOT_FOUND, "密钥不存在"),
    ACTIVE_KEY_REVOKE_FORBIDDEN(HttpStatus.CONFLICT, "不能吊销当前正在签发的活跃密钥，请先轮换");

    private final HttpStatus httpStatus;
    private final String defaultMessage;

    AuthErrorCode(HttpStatus httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
