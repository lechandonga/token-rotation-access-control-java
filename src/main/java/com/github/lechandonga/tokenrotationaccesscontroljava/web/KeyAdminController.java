package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.token.KeyManager;
import com.github.lechandonga.tokenrotationaccesscontroljava.token.SigningKey;
import java.time.Instant;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 本地密钥管理接口（无外部依赖，仅用于演示/自动化测试密钥轮换与吊销）。
 * 未挂权限注解的目的是让测试可直接驱动；生产形态应置于管理端口并加保护。
 */
@RestController
@RequestMapping("/admin/keys")
public class KeyAdminController {

    private final KeyManager keyManager;

    public KeyAdminController(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @PostMapping("/rotate")
    public KeyView rotate() {
        return KeyView.from(keyManager.rotate());
    }

    @PostMapping("/{keyId}/revoke")
    public KeyView revoke(@PathVariable String keyId) {
        keyManager.revoke(keyId);
        return keyManager.snapshot().stream()
                .filter(key -> key.keyId().equals(keyId))
                .map(KeyView::from)
                .findFirst()
                .orElseThrow();
    }

    @GetMapping
    public List<KeyView> list() {
        return keyManager.snapshot().stream().map(KeyView::from).toList();
    }

    public record KeyView(String keyId, String state, Instant activatedAt,
                          Instant retiredAt, Instant graceDeadline, long version) {
        static KeyView from(SigningKey key) {
            return new KeyView(key.keyId(), key.state().name(), key.activatedAt(),
                    key.retiredAt(), key.graceDeadline(), key.version());
        }
    }
}
