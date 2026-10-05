package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 内存主体目录，模拟本地用户库与凭据，不依赖任何外部服务。
 */
@Component
public class PrincipalDirectory {

    private final Map<String, Principal> principals = Map.of(
            "alice", new Principal("alice", "Alice", Set.of("read", "write")),
            "bob", new Principal("bob", "Bob", Set.of("read")),
            "admin", new Principal("admin", "Administrator", Set.of("read", "write", "admin"))
    );

    public Optional<Principal> authenticate(String subjectId, String secret) {
        if (subjectId == null || secret == null || secret.isBlank()) {
            return Optional.empty();
        }
        Principal principal = principals.get(subjectId);
        if (principal == null) {
            return Optional.empty();
        }
        // 本地模拟凭据规则：主体 id 加 "-secret"，仅用于演示。
        return (subjectId + "-secret").equals(secret) ? Optional.of(principal) : Optional.empty();
    }

    public Optional<Principal> find(String subjectId) {
        return Optional.ofNullable(principals.get(subjectId));
    }
}
