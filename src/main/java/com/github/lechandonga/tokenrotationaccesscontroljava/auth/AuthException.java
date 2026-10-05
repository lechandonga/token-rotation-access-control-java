package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

public class AuthException extends RuntimeException {

    private final AuthError error;

    public AuthException(AuthError error, String message) {
        super(message);
        this.error = error;
    }

    public AuthError error() {
        return error;
    }
}
