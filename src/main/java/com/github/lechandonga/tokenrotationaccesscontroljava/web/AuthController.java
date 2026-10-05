package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthErrorCode;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 本地凭证签发接口：登录与刷新轮换。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public AuthService.TokenPair login(@RequestBody Map<String, String> request) {
        String subjectId = request.get("subjectId");
        String secret = request.get("secret");
        if (subjectId == null || secret == null) {
            throw new AuthException(AuthErrorCode.BAD_REQUEST, "subjectId 与 secret 均为必填");
        }
        return authService.login(subjectId, secret);
    }

    @PostMapping("/refresh")
    public AuthService.TokenPair refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(AuthErrorCode.BAD_REQUEST, "refreshToken 为必填");
        }
        return authService.refresh(refreshToken);
    }
}
