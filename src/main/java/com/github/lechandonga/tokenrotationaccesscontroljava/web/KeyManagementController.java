package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.SigningKeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 本地签名密钥管理接口：轮换、查询与吊销。
 */
@RestController
@RequestMapping("/api/keys")
public class KeyManagementController {

    private final SigningKeyService signingKeyService;

    public KeyManagementController(SigningKeyService signingKeyService) {
        this.signingKeyService = signingKeyService;
    }

    @PostMapping("/rotate")
    public Map<String, Object> rotate() {
        String newKeyId = signingKeyService.rotate();
        return Map.of("rotated", true, "activeKeyId", newKeyId);
    }

    @GetMapping
    public List<SigningKeyService.KeyInfo> list() {
        return signingKeyService.listKeys();
    }

    @PostMapping("/{keyId}/revoke")
    public Map<String, Object> revoke(@PathVariable String keyId) {
        signingKeyService.revoke(keyId);
        return Map.of("revoked", true, "keyId", keyId);
    }
}
