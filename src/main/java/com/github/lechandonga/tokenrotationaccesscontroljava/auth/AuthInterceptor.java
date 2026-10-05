package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.AccessToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 受保护接口的统一鉴权入口。仅拦截声明了 {@link RequireScope} 的处理器方法，
 * 失败时返回可区分的错误码，绝不静默放行。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private final ObjectMapper objectMapper;
    private final TokenService tokenService;

    public AuthInterceptor(ObjectMapper objectMapper, TokenService tokenService) {
        this.objectMapper = objectMapper;
        this.tokenService = tokenService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        RequireScope requireScope = RequireScopes.resolve(handler);
        if (requireScope == null) {
            return true;
        }

        AuthContextHolder.clear();

        String authorization = request.getHeader("Authorization");
        if (authorization == null || authorization.isBlank()) {
            reject(response, AuthError.MISSING_CREDENTIAL, "缺少访问凭证: Authorization 头缺失");
            return false;
        }
        if (!authorization.startsWith("Bearer ") || authorization.length() <= 7) {
            reject(response, AuthError.MALFORMED_CREDENTIAL, "访问凭证格式错误: 需要 'Bearer <token>'");
            return false;
        }

        String token = authorization.substring(7).trim();
        AccessToken accessToken;
        try {
            accessToken = tokenService.verifyAccessToken(token);
        } catch (AuthException e) {
            reject(response, e.error(), e.getMessage());
            return false;
        }

        List<String> granted = accessToken.scopes();
        for (String scope : requireScope.value()) {
            if (!granted.contains(scope)) {
                AuthContextHolder.clear();
                reject(response, AuthError.INSUFFICIENT_SCOPE,
                        "权限不足: 需要 " + scope + ", 实际权限 " + granted);
                return false;
            }
        }

        AuthContextHolder.set(new AccessPrincipal(accessToken.subject(), granted,
                accessToken.tokenId(), accessToken.familyId()));
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        AuthContextHolder.clear();
    }

    private void reject(HttpServletResponse response, AuthError error, String message) throws Exception {
        response.setStatus(error.status().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), ErrorBody.of(error, message));
    }

    public record ErrorBody(String code, int status, String message) {
        static ErrorBody of(AuthError error, String message) {
            return new ErrorBody(error.code(), error.status().value(), message);
        }
    }

}
