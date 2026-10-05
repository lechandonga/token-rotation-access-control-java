package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import java.lang.reflect.Method;
import org.springframework.web.method.HandlerMethod;

/** 解析处理器方法/类上的 {@link RequireScope} 注解。 */
public final class RequireScopes {

    private RequireScopes() {
    }

    public static RequireScope resolve(Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return null;
        }
        Method method = handlerMethod.getMethod();
        RequireScope onMethod = method.getAnnotation(RequireScope.class);
        if (onMethod != null) {
            return onMethod;
        }
        return method.getDeclaringClass().getAnnotation(RequireScope.class);
    }
}
