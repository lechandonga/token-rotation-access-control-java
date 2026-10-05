package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.AbstractApiTest;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.BusinessBusiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 刷新凭证轮换与重用检测业务测试。
 */
@BusinessBusiness("刷新凭证轮换与重用检测")
class RefreshRotationTest extends AbstractApiTest {

    @Test
    @DisplayName("刷新成功后旧刷新凭证立即失效，新凭证可继续轮换")
    void rotationInvalidatesOldRefreshToken() throws Exception {
        TokenPair first = loginAlice();
        TokenPair second = refreshAndParse(first.refreshToken());

        assertNotEquals(first.refreshToken(), second.refreshToken());
        assertEquals(first.familyId(), second.familyId());

        MvcResult oldAgain = refresh(first.refreshToken());
        assertEquals(401, oldAgain.getResponse().getStatus());
        assertEquals("REFRESH_REUSED", errorCode(oldAgain));

        MvcResult third = refresh(second.refreshToken());
        assertEquals(401, third.getResponse().getStatus());
        // 旧凭证被重用后整族已吊销，最新凭证同样失效
        assertEquals("REFRESH_FAMILY_REVOKED", errorCode(third));
    }

    @Test
    @DisplayName("同一刷新凭证重复使用即判定重用，并吊销整个令牌族")
    void reuseRevokesEntireFamily() throws Exception {
        TokenPair first = loginAlice();
        TokenPair second = refreshAndParse(first.refreshToken());
        TokenPair third = refreshAndParse(second.refreshToken());

        // 攻击者拿出第一代旧凭证重放
        MvcResult replay = refresh(first.refreshToken());
        assertEquals("REFRESH_REUSED", errorCode(replay));

        // 族内此前各代凭证与最新凭证全部失效
        for (String token : new String[]{first.refreshToken(), second.refreshToken(), third.refreshToken()}) {
            MvcResult result = refresh(token);
            assertEquals(401, result.getResponse().getStatus());
            assertEquals("REFRESH_FAMILY_REVOKED", errorCode(result),
                    "令牌族吊销后所有凭证必须失效");
        }
    }

    @Test
    @DisplayName("不存在的刷新凭证以 REFRESH_NOT_FOUND 拒绝")
    void unknownRefreshTokenIsRejected() throws Exception {
        MvcResult result = refresh("rt_does_not_exist");
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("REFRESH_NOT_FOUND", errorCode(result));
    }

    @Test
    @DisplayName("刷新凭证超过有效期后以 REFRESH_EXPIRED 拒绝（推进虚拟时间，无需真实等待）")
    void expiredRefreshTokenIsRejected() throws Exception {
        TokenPair first = loginAlice();
        timeSource.advanceDays(8);
        MvcResult result = refresh(first.refreshToken());
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("REFRESH_EXPIRED", errorCode(result));
    }

    @Test
    @DisplayName("并发刷新同一凭证：恰好一个成功，其余被拒绝，绝不出现两个同时成功")
    void concurrentRefreshOnlyOneSucceeds() throws Exception {
        TokenPair first = loginAlice();
        int concurrency = 16;
        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(concurrency);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger reused = new AtomicInteger();
        AtomicInteger familyRevoked = new AtomicInteger();
        java.util.Collection<String> statusCodes = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.Collection<String> successTokens = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        for (int i = 0; i < concurrency; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    MvcResult result = refreshOnStandaloneMvc(first.refreshToken());
                    String code;
                    try {
                        code = errorCode(result);
                    } catch (Exception parseEx) {
                        code = "200-OK";
                    }
                    statusCodes.add(result.getResponse().getStatus() + ":" + code);
                    if (result.getResponse().getStatus() == 200) {
                        success.incrementAndGet();
                        successTokens.add(result.getResponse().getContentAsString());
                    } else if ("REFRESH_REUSED".equals(errorCode(result))) {
                        reused.incrementAndGet();
                    } else if ("REFRESH_FAMILY_REVOKED".equals(errorCode(result))) {
                        familyRevoked.incrementAndGet();
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发刷新任务应在限定时间内结束");
        pool.shutdown();
        System.out.println("并发刷新状态分布: " + statusCodes);

        assertEquals(1, success.get(), "同一刷新凭证并发刷新只能有一个请求成功");
        assertEquals(1, reused.get(), "必须恰好有一个迟到请求触发重用检测并吊销整族");
        assertEquals(concurrency - 2, familyRevoked.get(),
                "其余并发请求必须看到令牌族已吊销");
        assertEquals(1, successTokens.stream().distinct().count(), "成功结果必须唯一确定");

        // 并发结束后，胜者的新凭证可用，旧凭证再次使用时族已吊销
        MvcResult after = refresh(first.refreshToken());
        assertEquals("REFRESH_FAMILY_REVOKED", errorCode(after));
        String winnerAccessToken = JSON.readTree(successTokens.iterator().next())
                .get("accessToken").asText();
        MvcResult winnerAccess = getResource("/api/resources/read", "Bearer " + winnerAccessToken);
        assertEquals(401, winnerAccess.getResponse().getStatus());
        assertEquals("TOKEN_REVOKED", errorCode(winnerAccess),
                "重用检测吊销整族后，并发胜者已签发的访问凭证也必须失效");
    }
}
