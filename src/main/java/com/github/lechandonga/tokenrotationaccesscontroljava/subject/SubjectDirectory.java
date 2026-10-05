package com.github.lechandonga.tokenrotationaccesscontroljava.subject;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthError;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * 内存主体目录，模拟本地用户/服务账号及其权限范围。无真实凭据，
 * subjectId 即模拟登录标识，仅用于本地自包含演示。
 */
@Component
public class SubjectDirectory {

    private final Map<String, Subject> subjects = Map.of(
            "alice", new Subject("alice", "Alice (管理员)", List.of("profile:read", "doc:read", "doc:write")),
            "bob", new Subject("bob", "Bob (只读用户)", List.of("profile:read", "doc:read")),
            "service-report", new Subject("service-report", "报表服务账号", List.of("profile:read")));

    public Subject require(String subjectId) {
        return Optional.ofNullable(subjects.get(subjectId))
                .orElseThrow(() -> new AuthException(AuthError.INVALID_SUBJECT, "主体不存在: " + subjectId));
    }
}
