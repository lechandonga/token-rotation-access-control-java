package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AccessTokenService;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthErrorCode;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class AuthenticatedPrincipalArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AuthenticatedPrincipal.class)
                && AccessTokenService.AccessToken.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        Object token = request == null ? null
                : request.getAttribute(BearerAuthInterceptor.ACCESS_TOKEN_ATTRIBUTE);
        if (token == null) {
            throw new AuthException(AuthErrorCode.MISSING_CREDENTIAL);
        }
        return token;
    }
}
