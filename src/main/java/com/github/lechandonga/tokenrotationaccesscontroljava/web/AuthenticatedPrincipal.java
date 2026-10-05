package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 控制器方法参数注入当前认证主体。
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthenticatedPrincipal {
}
