package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthErrorCode;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/**
 * 统一错误响应：HTTP 状态 + 可区分错误码 + 可读原因，绝不静默放行。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuth(AuthException ex, HttpServletRequest request) {
        AuthErrorCode code = ex.getErrorCode();
        Map<String, Object> body = Map.of(
                "error", code.name(),
                "message", ex.getMessage(),
                "path", request.getRequestURI(),
                "timestamp", Instant.now().toString()
        );
        return ResponseEntity.status(code.getHttpStatus()).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex, HttpServletRequest request) {
        Map<String, Object> body = Map.of(
                "error", AuthErrorCode.BAD_REQUEST.name(),
                "message", ex.getMessage() == null ? "请求处理失败" : ex.getMessage(),
                "path", request.getRequestURI(),
                "timestamp", Instant.now().toString()
        );
        return ResponseEntity.badRequest().body(body);
    }
}
