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

@Business("访问/刷新凭证过期判定（时钟拨快，零真实等待）")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = {com.github.lechandonga.tokenrotationaccesscontroljava.Application.class, TestClockConfig.class})
@TestPropertySource(properties = {
        "token-rotation.security.access-ttl=2m",
        "token-rotation.security.refresh-ttl=10m",
        "token-rotation.security.key-grace-period=1h"
})
class TokenExpiryTests {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private MutableClock clock;

    private ApiClient api() {
        return new ApiClient(rest);
    }

    @Test
    @DisplayName("访问凭证在 TTL 内可用；时钟越过过期点后稳定返回 expired_token(401)")
    void accessTokenExpiresWhenClockAdvanced() {
        JsonNode login = api().login("alice");
        String accessToken = login.get("accessToken").asText();

        clock.advance(Duration.ofMinutes(1));
        assertThat(api().get("/api/profile", accessToken).getStatusCode()).isEqualTo(HttpStatus.OK);

        clock.advance(Duration.ofMinutes(1));
        ResponseEntity<JsonNode> expired = api().get("/api/profile", accessToken);
        assertThat(expired.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(expired)).isEqualTo("expired_token");

        ResponseEntity<JsonNode> stillExpired = api().get("/api/profile", accessToken);
        assertThat(ApiClient.errorCode(stillExpired)).isEqualTo("expired_token");
    }

    @Test
    @DisplayName("刷新凭证过期返回 expired_token，且不推进令牌族；重放仍按重用处理")
    void refreshTokenExpiresAndReplayStillDetected() {
        JsonNode login = api().login("alice");
        String refreshToken = login.get("refreshToken").asText();

        clock.advance(Duration.ofMinutes(5));
        assertThat(api().refreshRaw(refreshToken).getStatusCode()).isEqualTo(HttpStatus.OK);

        JsonNode secondLogin = api().login("alice");
        String another = secondLogin.get("refreshToken").asText();
        clock.advance(Duration.ofMinutes(11));

        ResponseEntity<JsonNode> expired = api().refreshRaw(another);
        assertThat(expired.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(expired)).isEqualTo("expired_token");

        ResponseEntity<JsonNode> expiredAgain = api().refreshRaw(another);
        assertThat(ApiClient.errorCode(expiredAgain)).isEqualTo("expired_token");
    }
}
