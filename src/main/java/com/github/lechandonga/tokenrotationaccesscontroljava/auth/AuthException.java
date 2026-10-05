package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

/**
 * 鉴权/令牌生命周期业务异常，携带可区分的错误码。
 */
public class AuthException extends RuntimeException {

    private final AuthErrorCode errorCode;

    public AuthException(AuthErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public AuthException(AuthErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public AuthErrorCode getErrorCode() {
        return errorCode;
    }
}
