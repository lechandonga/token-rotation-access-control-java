package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

/** 请求级别的已认证主体，线程绑定，请求结束由拦截器清理。 */
public final class AuthContextHolder {

    private static final ThreadLocal<AccessPrincipal> HOLDER = new ThreadLocal<>();

    private AuthContextHolder() {
    }

    public static void set(AccessPrincipal principal) {
        HOLDER.set(principal);
    }

    public static AccessPrincipal get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }
}
