package com.github.lechandonga.tokenrotationaccesscontroljava.web;

import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AuthContextHolder;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.AccessPrincipal;
import com.github.lechandonga.tokenrotationaccesscontroljava.auth.RequireScope;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 按权限范围保护的演示接口集合。 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/profile")
    @RequireScope("profile:read")
    public Map<String, Object> profile() {
        AccessPrincipal principal = AuthContextHolder.get();
        return Map.of("resource", "profile", "subject", principal.subject(),
                "scopes", principal.scopes());
    }

    @GetMapping("/docs")
    @RequireScope("doc:read")
    public Map<String, Object> readDoc() {
        AccessPrincipal principal = AuthContextHolder.get();
        return Map.of("resource", "docs", "subject", principal.subject(),
                "content", "只读文档内容");
    }

    @PostMapping("/docs")
    @RequireScope("doc:write")
    public Map<String, Object> writeDoc() {
        AccessPrincipal principal = AuthContextHolder.get();
        return Map.of("resource", "docs", "subject", principal.subject(),
                "result", "文档已更新");
    }
}
