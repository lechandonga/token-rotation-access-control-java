package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import java.util.Set;

/**
 * 本地模拟的认证主体（用户/客户端）。
 */
public record Principal(String subjectId, String displayName, Set<String> scopes) {
}
