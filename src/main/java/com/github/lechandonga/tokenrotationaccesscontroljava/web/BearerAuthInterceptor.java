package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AccessTokenService;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthErrorCode;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;

/**
 * Bearer 访问凭证拦截器：区分缺失/格式错误/过期/吊销/权限不足等拒绝原因。
 */
@Component
public class BearerAuthInterceptor implements HandlerInterceptor {

    public static final String ACCESS_TOKEN_ATTRIBUTE =
            "com.github.lechandonga.tokenrotationaccesscontroljava.accessToken";

    private static final String BEARER_PREFIX = "Bearer ";

    private final AccessTokenService accessTokenService;

    public BearerAuthInterceptor(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequiresScope requiresScope = handlerMethod.getMethodAnnotation(RequiresScope.class);
        if (requiresScope == null) {
            return true;
        }
        String authorization = request.getHeader("Authorization");
        if (authorization == null || authorization.isBlank()) {
            throw new AuthException(AuthErrorCode.MISSING_CREDENTIAL);
        }
        if (!authorization.startsWith(BEARER_PREFIX)) {
            throw new AuthException(AuthErrorCode.UNSUPPORTED_CREDENTIAL);
        }
        String token = authorization.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            throw new AuthException(AuthErrorCode.MALFORMED_CREDENTIAL);
        }
        AccessTokenService.AccessToken accessToken = accessTokenService.verify(token);
        Set<String> scopes = accessToken.scopes();
        if (!scopes.contains(requiresScope.value())) {
            throw new AuthException(AuthErrorCode.INSUFFICIENT_SCOPE,
                    "需要权限范围 '" + requiresScope.value() + "'，当前范围 " + scopes);
        }
        request.setAttribute(ACCESS_TOKEN_ATTRIBUTE, accessToken);
        return true;
    }
}
