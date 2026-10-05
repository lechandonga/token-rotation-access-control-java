package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.AbstractApiTest;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.BusinessBusiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 受保护接口访问控制：放行与各类可区分拒绝原因。
 */
@BusinessBusiness("访问凭证校验与权限范围控制")
class AccessControlTest extends AbstractApiTest {

    @Test
    @DisplayName("携带合法凭证且具备 read 范围时放行只读接口")
    void validTokenWithReadScopeIsAccepted() throws Exception {
        TokenPair alice = loginAlice();
        MvcResult result = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        assertEquals(200, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString().contains("只读资源内容"));
    }

    @Test
    @DisplayName("缺少 Authorization 头时以 MISSING_CREDENTIAL 拒绝")
    void missingCredentialIsRejected() throws Exception {
        MvcResult result = getResource("/api/resources/read", null);
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("MISSING_CREDENTIAL", errorCode(result));
    }

    @Test
    @DisplayName("非 Bearer 认证方式以 UNSUPPORTED_CREDENTIAL 拒绝")
    void unsupportedSchemeIsRejected() throws Exception {
        MvcResult result = getResource("/api/resources/read", "Basic dXNlcjpwYXNz");
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("UNSUPPORTED_CREDENTIAL", errorCode(result));
    }

    @Test
    @DisplayName("凭证结构不合法以 MALFORMED_CREDENTIAL 拒绝")
    void malformedTokenIsRejected() throws Exception {
        MvcResult result = getResource("/api/resources/read", "Bearer not-a.valid.token");
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("MALFORMED_CREDENTIAL", errorCode(result));
    }

    @Test
    @DisplayName("签名被篡改以 INVALID_SIGNATURE 拒绝")
    void tamperedSignatureIsRejected() throws Exception {
        TokenPair alice = loginAlice();
        String[] parts = alice.accessToken().split("\\.");
        String tampered = parts[0] + "." + parts[1] + "."
                + parts[2].substring(0, parts[2].length() - 2) + "AA";
        MvcResult result = getResource("/api/resources/read", "Bearer " + tampered);
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("INVALID_SIGNATURE", errorCode(result));
    }

    @Test
    @DisplayName("权限范围不足以 INSUFFICIENT_SCOPE 拒绝（bob 无 write）")
    void insufficientScopeIsRejected() throws Exception {
        TokenPair bob = loginBob();
        MvcResult result = getResource("/api/resources/write", "Bearer " + bob.accessToken());
        assertEquals(403, result.getResponse().getStatus());
        assertEquals("INSUFFICIENT_SCOPE", errorCode(result));
    }

    @Test
    @DisplayName("访问凭证超过有效期后以 TOKEN_EXPIRED 拒绝（推进虚拟时间，无需真实等待）")
    void expiredAccessTokenIsRejected() throws Exception {
        TokenPair alice = loginAlice();
        timeSource.advanceMinutes(31);
        MvcResult result = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("TOKEN_EXPIRED", errorCode(result));
    }

    @Test
    @DisplayName("刷新凭证重用导致整族吊销后，既有访问凭证以 TOKEN_REVOKED 拒绝")
    void revokedFamilyRejectsAccessToken() throws Exception {
        TokenPair alice = loginAlice();
        TokenPair rotated = refreshAndParse(alice.refreshToken());
        // 再次使用已轮换的旧刷新凭证 -> 重用检测，整族吊销
        MvcResult reuse = refresh(alice.refreshToken());
        assertEquals(401, reuse.getResponse().getStatus());
        assertEquals("REFRESH_REUSED", errorCode(reuse));

        MvcResult access = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        assertEquals(401, access.getResponse().getStatus());
        assertEquals("TOKEN_REVOKED", errorCode(access));

        MvcResult newAccess = getResource("/api/resources/read", "Bearer " + rotated.accessToken());
        assertEquals(401, newAccess.getResponse().getStatus());
        assertEquals("TOKEN_REVOKED", errorCode(newAccess));
    }

    @Test
    @DisplayName("错误的登录凭据以 UNKNOWN_SUBJECT 拒绝，不签发任何凭证")
    void wrongLoginCredentialIsRejected() throws Exception {
        MvcResult result = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"subjectId\":\"alice\",\"secret\":\"wrong-secret\"}"))
                .andReturn();
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("UNKNOWN_SUBJECT", errorCode(result));
    }
}
