package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

/**
 * 标注处理器方法所需的权限范围（scope），全部满足才放行。
 */
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@java.lang.annotation.Target({java.lang.annotation.ElementType.METHOD, java.lang.annotation.ElementType.TYPE})
public @interface RequireScope {

    String[] value();
}
