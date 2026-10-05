package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.ApiClient;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.Business;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.MutableClock;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.TestClockConfig;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

@Business("签名密钥轮换、宽限期并存与吊销")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = {com.github.lechandonga.tokenrotationaccesscontroljava.Application.class, TestClockConfig.class})
@TestPropertySource(properties = {
        "token-rotation.security.access-ttl=2h",
        "token-rotation.security.refresh-ttl=24h",
        "token-rotation.security.key-grace-period=1h"
})
class KeyRotationTests {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private MutableClock clock;

    private ApiClient api() {
        return new ApiClient(rest);
    }

    @Test
    @DisplayName("轮换后新凭证使用新密钥；旧密钥在宽限期内仍可校验旧凭证")
    void oldKeyRemainsValidDuringGracePeriod() {
        JsonNode before = api().login("alice");
        String oldKid = before.get("claims").get("keyId").asText();

        ResponseEntity<JsonNode> rotation = api().post("/admin/keys/rotate", "{}", null);
        assertThat(rotation.getStatusCode()).isEqualTo(HttpStatus.OK);
        String newKid = rotation.getBody().get("keyId").asText();
        assertThat(newKid).isNotEqualTo(oldKid);

        JsonNode after = api().login("alice");
        assertThat(after.get("claims").get("keyId").asText()).isEqualTo(newKid);

        assertThat(api().get("/api/profile", before.get("accessToken").asText()).getStatusCode())
                .as("宽限期内旧密钥签发的访问凭证仍可校验").isEqualTo(HttpStatus.OK);
        assertThat(api().refreshRaw(before.get("refreshToken").asText()).getStatusCode())
                .as("宽限期内旧密钥签发的刷新凭证仍可校验并轮换").isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("宽限期结束后旧密钥稳定拒绝；新密钥凭证不受影响（全程零真实等待）")
    void oldKeyRejectedAfterGracePeriodStably() {
        JsonNode before = api().login("alice");
        String oldAccess = before.get("accessToken").asText();
        String oldRefresh = before.get("refreshToken").asText();

        String newKid = api().post("/admin/keys/rotate", "{}", null).getBody().get("keyId").asText();
        clock.advance(Duration.ofMinutes(61));

        JsonNode after = api().login("alice");
        assertThat(after.get("claims").get("keyId").asText()).isEqualTo(newKid);

        ResponseEntity<JsonNode> oldAccessRejected = api().get("/api/profile", oldAccess);
        assertThat(oldAccessRejected.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(oldAccessRejected)).isEqualTo("invalid_signature");

        ResponseEntity<JsonNode> oldRefreshRejected = api().refreshRaw(oldRefresh);
        assertThat(oldRefreshRejected.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(oldRefreshRejected)).isEqualTo("invalid_signature");

        assertThat(api().get("/api/profile", after.get("accessToken").asText()).getStatusCode())
                .as("当前密钥凭证在校验旧密钥被拒后依旧正常，结果不抖动")
                .isEqualTo(HttpStatus.OK);

        ResponseEntity<JsonNode> oldAccessAgain = api().get("/api/profile", oldAccess);
        assertThat(ApiClient.errorCode(oldAccessAgain)).isEqualTo("invalid_signature");
    }

    @Test
    @DisplayName("立即吊销旧密钥后，其签发凭证马上稳定失效")
    void revokingOldKeyRejectsExistingTokensImmediately() {
        JsonNode before = api().login("alice");
        String oldKid = before.get("claims").get("keyId").asText();
        api().post("/admin/keys/rotate", "{}", null);

        assertThat(api().get("/api/profile", before.get("accessToken").asText()).getStatusCode())
                .isEqualTo(HttpStatus.OK);

        ResponseEntity<JsonNode> revoke = api().post("/admin/keys/" + oldKid + "/revoke", "{}", null);
        assertThat(revoke.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(revoke.getBody().get("state").asText()).isEqualTo("REVOKED");

        ResponseEntity<JsonNode> rejected = api().get("/api/profile", before.get("accessToken").asText());
        assertThat(rejected.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(rejected)).isEqualTo("invalid_signature");

        assertThat(ApiClient.errorCode(api().get("/api/profile", before.get("accessToken").asText())))
                .isEqualTo("invalid_signature");
    }
}
