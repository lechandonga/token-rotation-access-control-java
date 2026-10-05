package com.github.lechandonga.tokenrotationaccesscontroljava.token;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthError;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthException;
import com.github.lechandonga.tokenrotationaccesscontroljava.config.SecurityProps;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.springframework.stereotype.Component;

/**
 * 内存版签名密钥库：支持轮换、宽限期并存、吊销与宽限期到期。
 * 读写均加锁，保证轮换/吊销期间校验结果稳定，不出现时好时坏。
 */
@Component
public class KeyManager {

    private final Clock clock;
    private final SecurityProps props;
    private final SecureRandom random = new SecureRandom();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private long keySequence;

    /** keyId -> 密钥版本，有序，便于观测。 */
    private final NavigableMap<String, SigningKey> keys = new TreeMap<>();

    public KeyManager(Clock clock, SecurityProps props) {
        this.clock = clock;
        this.props = props;
        rotate(nextKeyId());
    }

    /** 生成新的 ACTIVE 密钥；旧 ACTIVE 密钥进入 RETIRED 并开始计算宽限期。 */
    public SigningKey rotate(String newKeyId) {
        lock.writeLock().lock();
        try {
            Instant now = Instant.now(clock);
            SigningKey current = currentActive();
            if (current != null) {
                keys.put(current.keyId(), current.retire(now, now.plus(props.keyGracePeriod())));
            }
            byte[] secret = new byte[32];
            random.nextBytes(secret);
            SigningKey fresh = new SigningKey(newKeyId, secret, SigningKey.State.ACTIVE,
                    now, null, null, 1);
            keys.put(newKeyId, fresh);
            return fresh;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public SigningKey rotate() {
        return rotate(nextKeyId());
    }

    /** 立即吊销指定密钥，之后用它签发的凭证一律 invalid_signature 级别的稳定拒绝。 */
    public void revoke(String keyId) {
        lock.writeLock().lock();
        try {
            SigningKey key = keys.get(keyId);
            if (key == null) {
                throw new AuthException(AuthError.UNKNOWN_KEY, "未知密钥: " + keyId);
            }
            keys.put(keyId, key.revoke());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 宽限期到期推进：RETIRED 且超过宽限截止时间的密钥置为 EXPIRED（终态）。 */
    public int expireDueKeys() {
        lock.writeLock().lock();
        try {
            Instant now = Instant.now(clock);
            int expired = 0;
            for (Map.Entry<String, SigningKey> entry : keys.entrySet()) {
                SigningKey key = entry.getValue();
                if (key.state() == SigningKey.State.RETIRED
                        && key.graceDeadline() != null && !now.isBefore(key.graceDeadline())) {
                    entry.setValue(key.expire());
                    expired++;
                }
            }
            return expired;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public SigningKey currentSigningKey() {
        lock.readLock().lock();
        try {
            SigningKey active = currentActive();
            if (active == null) {
                throw new AuthException(AuthError.UNKNOWN_KEY, "不存在可用的签名密钥");
            }
            return active;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 按 keyId 取可校验密钥。区分三种拒绝：
     * 密钥不存在 -> UNKNOWN_KEY；已吊销 -> INVALID_SIGNATURE；宽限期已过 -> INVALID_SIGNATURE。
     */
    public SigningKey keyForVerification(String keyId) {
        expireDueKeys();
        lock.readLock().lock();
        try {
            SigningKey key = keys.get(keyId);
            if (key == null) {
                throw new AuthException(AuthError.UNKNOWN_KEY, "未知密钥标识: " + keyId);
            }
            if (key.state() == SigningKey.State.REVOKED) {
                throw new AuthException(AuthError.INVALID_SIGNATURE, "签名密钥已吊销: " + keyId);
            }
            if (!key.canVerify(Instant.now(clock))) {
                throw new AuthException(AuthError.INVALID_SIGNATURE,
                        "签名密钥宽限期已结束: " + keyId);
            }
            return key;
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<SigningKey> snapshot() {
        lock.readLock().lock();
        try {
            return List.copyOf(keys.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    private SigningKey currentActive() {
        SigningKey found = null;
        for (SigningKey key : keys.values()) {
            if (key.state() == SigningKey.State.ACTIVE) {
                found = key;
            }
        }
        return found;
    }

    private static String randomSuffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private String nextKeyId() {
        return "k" + (++keySequence) + "-" + randomSuffix();
    }
}
