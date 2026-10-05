package com.github.lechandonga.tokenrotationaccesscontroljava.token;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthError;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 内存令牌族存储。每个族一把锁：刷新轮换全程在族锁内完成读-判-写，
 * 保证同一刷新凭证并发使用时恰好一个成功，其余全部失败且触发整族吊销。
 */
@Component
public class TokenStore {

    private final Map<String, TokenFamily> families = new ConcurrentHashMap<>();
    private final Map<String, Object> familyLocks = new ConcurrentHashMap<>();

    public void create(TokenFamily family) {
        families.put(family.familyId(), family);
        familyLocks.put(family.familyId(), new Object());
    }

    public Object lockOf(String familyId) {
        return familyLocks.computeIfAbsent(familyId, ignored -> new Object());
    }

    public TokenFamily require(String familyId) {
        TokenFamily family = families.get(familyId);
        if (family == null) {
            throw new AuthException(AuthError.REVOKED_TOKEN, "令牌族不存在或已清除: " + familyId);
        }
        return family;
    }

    public TokenFamily save(TokenFamily family) {
        families.put(family.familyId(), family);
        return family;
    }

    public void revokeFamily(String familyId, TokenFamily.State state) {
        TokenFamily family = families.get(familyId);
        if (family != null) {
            families.put(familyId, family.mark(state, family.updatedAtEpochMilli()));
        }
    }
}
