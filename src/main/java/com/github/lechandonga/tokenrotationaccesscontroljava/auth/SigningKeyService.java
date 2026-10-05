package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.github.lechandonga.tokenrotationaccesscontroljava.config.AuthProperties;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * 内存签名密钥管理：支持轮换、新旧并存、宽限期与显式吊销。
 *
 * <p>内部以不可变快照保存所有状态，读写均经过同一把锁，保证轮换/吊销过程中
 * 同一凭证的校验结果不会时好时坏，也不会出现读到半更新状态。
 */
@Component
public class SigningKeyService {

    public record KeyInfo(String keyId, String status, Long rotatedAtMillis, Long retireAtMillis,
                          String fingerprint) {
    }

    private record RetiredKey(String keyId, SecretKey key, long rotatedAt, long retireAt, boolean revoked) {
    }

    private record Snapshot(SecretKey activeKey, String activeKeyId, long activatedAt,
                            NavigableMap<String, RetiredKey> retired) {
    }

    private final TimeSource timeSource;
    private final AuthProperties properties;

    private volatile Snapshot snapshot;

    public SigningKeyService(TimeSource timeSource, AuthProperties properties) {
        this.timeSource = timeSource;
        this.properties = properties;
        long now = timeSource.epochMillis();
        String keyId = "k-" + now + "-0";
        this.snapshot = new Snapshot(generateKey(), keyId, now, new TreeMap<>());
    }

    /**
     * 轮换密钥：当前活跃密钥进入宽限期，新生成的密钥成为唯一签发密钥。
     *
     * @return 新的活跃密钥 id
     */
    public String rotate() {
        synchronized (this) {
            Snapshot current = snapshot;
            long now = timeSource.epochMillis();
            RetiredKey retired = new RetiredKey(
                    current.activeKeyId, current.activeKey, now,
                    now + properties.getKeyGracePeriod().toMillis(), false);
            TreeMap<String, RetiredKey> nextRetired = new TreeMap<>(current.retired);
            nextRetired.put(current.activeKeyId, retired);
            String newKeyId = "k-" + now + "-" + nextRetired.size();
            snapshot = new Snapshot(generateKey(), newKeyId, now, nextRetired);
            return newKeyId;
        }
    }

    /** 当前用于签发的活跃密钥。 */
    public KeyInfo currentSigningKey() {
        Snapshot current = snapshot;
        return new KeyInfo(current.activeKeyId, "ACTIVE", current.activatedAt, null,
                fingerprint(current.activeKey));
    }

    /**
     * 立即吊销指定密钥（活跃密钥除外）。吊销后用该密钥签发的凭证立刻稳定失效。
     */
    public synchronized void revoke(String keyId) {
        Snapshot current = snapshot;
        if (current.activeKeyId.equals(keyId)) {
            throw new AuthException(AuthErrorCode.ACTIVE_KEY_REVOKE_FORBIDDEN);
        }
        RetiredKey key = current.retired.get(keyId);
        if (key == null) {
            throw new AuthException(AuthErrorCode.KEY_NOT_FOUND);
        }
        TreeMap<String, RetiredKey> nextRetired = new TreeMap<>(current.retired);
        nextRetired.put(keyId, new RetiredKey(key.keyId, key.key, key.rotatedAt, key.retireAt, true));
        snapshot = new Snapshot(current.activeKey, current.activeKeyId, current.activatedAt, nextRetired);
    }

    /** 列出全部密钥及其状态（ACTIVE / GRACE / EXPIRED / REVOKED）。 */
    public List<KeyInfo> listKeys() {
        Snapshot current = snapshot;
        long now = timeSource.epochMillis();
        List<KeyInfo> result = new ArrayList<>();
        result.add(new KeyInfo(current.activeKeyId, "ACTIVE", current.activatedAt, null,
                fingerprint(current.activeKey)));
        for (RetiredKey key : current.retired.values()) {
            String status = key.revoked ? "REVOKED" : (now >= key.retireAt ? "EXPIRED" : "GRACE");
            result.add(new KeyInfo(key.keyId, status, key.rotatedAt, key.retireAt,
                    fingerprint(key.key)));
        }
        return result;
    }

    /**
     * 按 id 查找可用于校验的密钥。
     *
     * @return 密钥；密钥不存在、已被吊销或宽限期已结束时返回 null
     */
    public SecretKey findVerifyingKey(String keyId) {
        Snapshot current = snapshot;
        long now = timeSource.epochMillis();
        if (current.activeKeyId.equals(keyId)) {
            return current.activeKey;
        }
        RetiredKey key = current.retired.get(keyId);
        if (key == null || key.revoked || now >= key.retireAt) {
            return null;
        }
        return key.key;
    }

    private static SecretKey generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
            generator.init(256);
            SecretKey secretKey = generator.generateKey();
            // 转为可跨实现比较/指纹计算的标准规格密钥。
            return new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JRE 不支持 HmacSHA256", e);
        }
    }

    private static String fingerprint(SecretKey key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(key.getEncoded())).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JRE 不支持 SHA-256", e);
        }
    }
}
