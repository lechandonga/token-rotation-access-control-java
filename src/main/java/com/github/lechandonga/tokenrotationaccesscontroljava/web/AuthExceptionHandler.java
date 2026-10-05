package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthError;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorBody> handle(AuthException e) {
        AuthError error = e.error();
        return ResponseEntity.status(error.status())
                .body(new AuthExceptionHandler.ErrorBody(error.code(), error.status().value(), e.getMessage()));
    }

    public record ErrorBody(String code, int status, String message) {
    }
}
