package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AccessTokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 受保护示例接口：按权限范围放行或拒绝。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    @GetMapping("/read")
    @RequiresScope("read")
    public Map<String, Object> read(@AuthenticatedPrincipal AccessTokenService.AccessToken token) {
        return Map.of("data", "只读资源内容", "subject", token.subject(),
                "familyId", token.familyId(), "keyId", token.keyId());
    }

    @GetMapping("/write")
    @RequiresScope("write")
    public Map<String, Object> write(@AuthenticatedPrincipal AccessTokenService.AccessToken token) {
        return Map.of("data", "可写资源操作成功", "subject", token.subject(),
                "familyId", token.familyId(), "keyId", token.keyId());
    }
}
