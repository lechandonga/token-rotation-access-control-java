package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.ApiClient;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.Business;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.TestClockConfig;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Business("刷新令牌轮换与重用检测（含并发）")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = {com.github.lechandonga.tokenrotationaccesscontroljava.Application.class, TestClockConfig.class})
class RefreshRotationTests {

    @Autowired
    private TestRestTemplate rest;

    private ApiClient api() {
        return new ApiClient(rest);
    }

    @Test
    @DisplayName("正常轮换：旧刷新凭证只能成功一次，再次使用即重用并整族吊销")
    void singleUseRefreshAndReuseRevokesFamily() {
        ApiClient api = api();
        JsonNode login = api.login("alice");
        String firstRefresh = login.get("refreshToken").asText();
        String familyId = login.get("claims").get("familyId").asText();

        ResponseEntity<JsonNode> firstUse = api.refreshRaw(firstRefresh);
        assertThat(firstUse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String secondRefresh = firstUse.getBody().get("refreshToken").asText();

        ResponseEntity<JsonNode> reused = api.refreshRaw(firstRefresh);
        assertThat(reused.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(reused)).isEqualTo("refresh_token_reused");

        ResponseEntity<JsonNode> newestBlocked = api.refreshRaw(secondRefresh);
        assertThat(newestBlocked.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(newestBlocked)).isEqualTo("refresh_token_reused");

        ResponseEntity<JsonNode> accessBlocked = api.get("/api/profile",
                firstUse.getBody().get("accessToken").asText());
        assertThat(accessBlocked.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(accessBlocked)).isEqualTo("token_family_revoked");

        assertThat(familyId).isNotBlank();
    }

    @Test
    @DisplayName("并发刷新同一凭证：恰好一个成功，其余全部失败，不产生两个成功结果")
    void concurrentRefreshExactlyOneWinner() throws Exception {
        ApiClient api = api();
        JsonNode login = api.login("alice");
        String sharedRefresh = login.get("refreshToken").asText();

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<ResponseEntity<JsonNode>>> futures = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                return api.refreshRaw(sharedRefresh);
            }));
        }
        assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
        start.countDown();

        int success = 0;
        Set<String> winnerRefreshTokens = new HashSet<>();
        for (Future<ResponseEntity<JsonNode>> future : futures) {
            ResponseEntity<JsonNode> response = future.get(10, TimeUnit.SECONDS);
            if (response.getStatusCode().is2xxSuccessful()) {
                success++;
                winnerRefreshTokens.add(response.getBody().get("refreshToken").asText());
            } else {
                assertThat(ApiClient.errorCode(response)).isEqualTo("refresh_token_reused");
            }
        }
        pool.shutdownNow();

        assertThat(success).as("并发刷新只允许一个请求成功").isEqualTo(1);
        assertThat(winnerRefreshTokens).hasSize(1);

        ResponseEntity<JsonNode> winnerRotated =
                api.refreshRaw(winnerRefreshTokens.iterator().next());
        assertThat(winnerRotated.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(winnerRotated)).isEqualTo("refresh_token_reused");
    }

    @Test
    @DisplayName("连续正常轮换多次均成功，新凭证持续可用；事后重放任一旧凭证则整族吊销")
    void sequentialRotationsStayUsableUntilReplay() {
        ApiClient api = api();
        JsonNode login = api.login("bob");
        String firstRefresh = login.get("refreshToken").asText();
        String refresh = firstRefresh;
        String latestAccess = login.get("accessToken").asText();

        for (int round = 0; round < 5; round++) {
            ResponseEntity<JsonNode> rotated = api.refreshRaw(refresh);
            assertThat(rotated.getStatusCode()).isEqualTo(HttpStatus.OK);
            refresh = rotated.getBody().get("refreshToken").asText();
            latestAccess = rotated.getBody().get("accessToken").asText();
            assertThat(api.get("/api/docs", latestAccess).getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        ResponseEntity<JsonNode> firstReplay = api.refreshRaw(firstRefresh);
        assertThat(ApiClient.errorCode(firstReplay)).isEqualTo("refresh_token_reused");

        ResponseEntity<JsonNode> latestRefreshBlocked = api.refreshRaw(refresh);
        assertThat(ApiClient.errorCode(latestRefreshBlocked)).isEqualTo("refresh_token_reused");

        ResponseEntity<JsonNode> accessBlocked = api.get("/api/docs", latestAccess);
        assertThat(accessBlocked.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ApiClient.errorCode(accessBlocked)).isEqualTo("token_family_revoked");
    }
}
