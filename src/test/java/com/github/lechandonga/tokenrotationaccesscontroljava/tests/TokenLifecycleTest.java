package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.AbstractApiTest;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.BusinessBusiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 令牌端到端生命周期：签发、滑动续期、过期与族吊销联动。
 */
@BusinessBusiness("令牌端到端生命周期")
class TokenLifecycleTest extends AbstractApiTest {

    @Test
    @DisplayName("登录签发的凭证类型固定为 Bearer，且响应包含族 id 与密钥 id")
    void loginIssuesBearerTokenPair() throws Exception {
        MvcResult result = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"subjectId\":\"bob\",\"secret\":\"bob-secret\"}"))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus());
        String body = result.getResponse().getContentAsString();
        assertEquals("Bearer", JSON.readTree(body).get("tokenType").asText());
        assertEquals(true, JSON.readTree(body).has("familyId"));
        assertEquals(true, JSON.readTree(body).has("keyId"));
    }

    @Test
    @DisplayName("刷新凭证有效期采用滑动续期：到期前轮换可获得新的完整有效期")
    void refreshSlidingExpiration() throws Exception {
        // 第一代刷新凭证在第 6 天（7 天有效期内）轮换，第二代拿到完整的新 7 天
        TokenPair clean = loginAlice();
        timeSource.advanceDays(6);
        TokenPair cleanSecond = refreshAndParse(clean.refreshToken());
        timeSource.advanceDays(6);
        MvcResult sliding = refresh(cleanSecond.refreshToken());
        assertEquals(200, sliding.getResponse().getStatus(),
                "轮换后应获得新的完整刷新有效期");
    }

    @Test
    @DisplayName("对照：未做轮换的刷新凭证自签发起满 7 天即失效（推进虚拟时间）")
    void nonRotatedRefreshExpiresAfterTtl() throws Exception {
        TokenPair untouched = loginAlice();
        timeSource.advanceDays(7);
        timeSource.advanceMillis(1);
        MvcResult expired = refresh(untouched.refreshToken());
        assertEquals(401, expired.getResponse().getStatus());
        assertEquals("REFRESH_EXPIRED", errorCode(expired));
    }

    @Test
    @DisplayName("超过刷新有效期后无法轮换，且错误码与访问凭证过期相互区分")
    void refreshAndAccessExpiryHaveDistinctReasons() throws Exception {
        TokenPair first = loginAlice();
        // 访问凭证先过期（30 分钟），刷新凭证仍有效：读接口报 TOKEN_EXPIRED，刷新仍成功
        timeSource.advanceMinutes(31);
        MvcResult expiredAccess = getResource("/api/resources/read",
                "Bearer " + first.accessToken());
        assertEquals("TOKEN_EXPIRED", errorCode(expiredAccess));

        TokenPair second = refreshAndParse(first.refreshToken());
        MvcResult renewedAccess = getResource("/api/resources/read",
                "Bearer " + second.accessToken());
        assertEquals(200, renewedAccess.getResponse().getStatus());

        // 刷新凭证也过期（8 天）：报 REFRESH_EXPIRED
        timeSource.advanceDays(8);
        MvcResult expiredRefresh = refresh(second.refreshToken());
        assertEquals("REFRESH_EXPIRED", errorCode(expiredRefresh));
    }

    @Test
    @DisplayName("登录缺少必填参数以 BAD_REQUEST 拒绝")
    void loginMissingParameterIsBadRequest() throws Exception {
        MvcResult result = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"subjectId\":\"alice\"}"))
                .andReturn();
        assertEquals(400, result.getResponse().getStatus());
        assertEquals("BAD_REQUEST", errorCode(result));
    }

    @Test
    @DisplayName("密钥轮换后再次轮换，多个旧密钥按各自宽限期独立判定")
    void multipleRotationsExpireIndependently() throws Exception {
        TokenPair first = loginAlice();
        rotateKey();
        TokenPair second = refreshAndParse(first.refreshToken());
        rotateKey();
        TokenPair secondRefresh = second;

        timeSource.advanceHours(25);
        // 第一代密钥已出宽限期，第二代同样超出 24 小时（两次轮换发生在同一虚拟时刻）
        assertEquals("UNKNOWN_SIGNING_KEY", errorCode(getResource("/api/resources/read",
                "Bearer " + first.accessToken())));
        assertEquals("UNKNOWN_SIGNING_KEY", errorCode(getResource("/api/resources/read",
                "Bearer " + second.accessToken())));

        // 此时最新密钥仍为活跃密钥；用仍有效的刷新凭证（7 天有效期）换新访问凭证后可正常访问
        TokenPair fresh = refreshAndParse(secondRefresh.refreshToken());
        MvcResult current = getResource("/api/resources/read", "Bearer " + fresh.accessToken());
        assertEquals(200, current.getResponse().getStatus());
    }
}
