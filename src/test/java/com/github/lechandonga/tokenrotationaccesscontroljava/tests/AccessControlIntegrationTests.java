package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.ApiClient;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.Business;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.TestClockConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Business("受保护接口鉴权与可区分拒绝原因")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = {com.github.lechandonga.tokenrotationaccesscontroljava.Application.class, TestClockConfig.class})
class AccessControlIntegrationTests {

    @Autowired
    private TestRestTemplate rest;

    private ApiClient api() {
        return new ApiClient(rest);
    }

    @Test
    @DisplayName("有权限的访问凭证按 scope 放行，返回资源内容")
    void allowsWhenScopeSatisfied() {
        JsonNode login = api().login("alice");
        ResponseEntity<JsonNode> response = api().get("/api/profile", login.get("accessToken").asText());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("subject").asText()).isEqualTo("alice");
    }

    @Test
    @DisplayName("缺少 Authorization 头 -> missing_credential(401)，绝不静默放行")
    void rejectsMissingCredential() {
        ResponseEntity<JsonNode> response = api().get("/api/profile", null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(response)).isEqualTo("missing_credential");
    }

    @Test
    @DisplayName("凭证非 Bearer 结构 -> malformed_credential(401)")
    void rejectsMalformedScheme() {
        ResponseEntity<JsonNode> response = api().get("/api/profile", "NotBearer xyz");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(response)).isEqualTo("malformed_credential");
    }

    @Test
    @DisplayName("凭证结构损坏(无签名段) -> malformed_credential(401)")
    void rejectsMalformedStructure() {
        ResponseEntity<JsonNode> response = api().get("/api/profile", "garbage-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(response)).isEqualTo("malformed_credential");
    }

    @Test
    @DisplayName("签名被篡改 -> invalid_signature(401)，与格式错误区分开")
    void rejectsTamperedSignature() {
        JsonNode login = api().login("alice");
        String token = login.get("accessToken").asText();
        char last = token.charAt(token.length() - 1);
        String tampered = token.substring(0, token.length() - 1)
                + (last == 'A' || last == 'a' ? 'B' : 'A');

        ResponseEntity<JsonNode> response = api().get("/api/profile", tampered);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(response)).isEqualTo("invalid_signature");
    }

    @Test
    @DisplayName("权限不足 -> insufficient_scope(403)，与未认证的 401 区分开")
    void rejectsInsufficientScopeWith403() {
        JsonNode login = api().login("bob");

        ResponseEntity<JsonNode> response = api().post("/api/docs", "{}", login.get("accessToken").asText());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ApiClient.errorCode(response)).isEqualTo("insufficient_scope");
    }

    @Test
    @DisplayName("显式吊销令牌族后，族内访问凭证立即失效 -> revoked_token(401)")
    void rejectsAfterFamilyRevocation() {
        JsonNode login = api().login("alice");
        String accessToken = login.get("accessToken").asText();

        ResponseEntity<JsonNode> revoke = api().post("/auth/revoke", "{}", accessToken);
        assertThat(revoke.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<JsonNode> after = api().get("/api/profile", accessToken);
        assertThat(after.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(after)).isEqualTo("revoked_token");
    }

    @Test
    @DisplayName("未知主体模拟登录 -> invalid_subject(401)")
    void rejectsUnknownSubject() {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.set("Content-Type", org.springframework.http.MediaType.APPLICATION_JSON_VALUE);
        ResponseEntity<JsonNode> explicit = rest.postForEntity("/auth/login",
                new org.springframework.http.HttpEntity<>("{\"subjectId\":\"ghost\"}", headers),
                JsonNode.class);

        assertThat(explicit.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(explicit)).isEqualTo("invalid_subject");
    }
}
