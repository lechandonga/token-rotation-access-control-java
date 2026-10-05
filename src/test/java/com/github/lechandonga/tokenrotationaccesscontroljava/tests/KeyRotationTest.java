package com.github.lechandonga.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.AbstractApiTest;
import com.github.lechandonga.tokenrotationaccesscontroljava.tests.support.BusinessBusiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 签名密钥轮换、新旧并存与宽限期业务测试。
 */
@BusinessBusiness("签名密钥轮换与宽限期")
class KeyRotationTest extends AbstractApiTest {

    @Test
    @DisplayName("轮换后新签发凭证使用新密钥，旧密钥在宽限期内仍可校验既有凭证")
    void oldKeyStillVerifiesWithinGracePeriod() throws Exception {
        TokenPair before = loginAlice();
        MvcResult rotate = rotateKey();
        assertEquals(200, rotate.getResponse().getStatus());
        String newKeyId = JSON.readTree(rotate.getResponse().getContentAsString())
                .get("activeKeyId").asText();

        // 宽限期内：旧凭证仍可校验
        MvcResult oldAccess = getResource("/api/resources/read", "Bearer " + before.accessToken());
        assertEquals(200, oldAccess.getResponse().getStatus());

        // 轮换后的新签发使用新密钥
        TokenPair after = refreshAndParse(before.refreshToken());
        assertNotEquals(newKeyId, before.accessToken().split("\\.")[0]);
        MvcResult freshAccess = getResource("/api/resources/read", "Bearer " + after.accessToken());
        assertEquals(200, freshAccess.getResponse().getStatus());
        JsonNode freshBody = JSON.readTree(freshAccess.getResponse().getContentAsString());
        assertEquals(newKeyId, freshBody.get("keyId").asText());
    }

    @Test
    @DisplayName("宽限期结束后旧密钥凭证稳定拒绝（推进虚拟时间，无需真实等待）")
    void oldKeyRejectedAfterGracePeriod() throws Exception {
        TokenPair before = loginAlice();
        rotateKey();

        timeSource.advanceHours(25);
        MvcResult result = getResource("/api/resources/read", "Bearer " + before.accessToken());
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("UNKNOWN_SIGNING_KEY", errorCode(result));

        // 再次校验结论一致，不会时好时坏
        MvcResult again = getResource("/api/resources/read", "Bearer " + before.accessToken());
        assertEquals("UNKNOWN_SIGNING_KEY", errorCode(again));
    }

    @Test
    @DisplayName("宽限期内显式吊销旧密钥后，旧凭证立即失效")
    void revokedOldKeyRejectsImmediately() throws Exception {
        TokenPair before = loginAlice();
        String oldKeyId = JSON.readTree(getResource("/api/resources/read",
                "Bearer " + before.accessToken()).getResponse().getContentAsString())
                .get("keyId").asText();
        rotateKey();

        MvcResult revoke = revokeKey(oldKeyId);
        assertEquals(200, revoke.getResponse().getStatus());

        MvcResult result = getResource("/api/resources/read", "Bearer " + before.accessToken());
        assertEquals(401, result.getResponse().getStatus());
        assertEquals("UNKNOWN_SIGNING_KEY", errorCode(result));
    }

    @Test
    @DisplayName("不能直接吊销当前活跃签发密钥，必须先轮换")
    void activeKeyCannotBeRevokedBeforeRotation() throws Exception {
        TokenPair alice = loginAlice();
        MvcResult access = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        String activeKeyId = JSON.readTree(access.getResponse().getContentAsString())
                .get("keyId").asText();

        MvcResult revoke = revokeKey(activeKeyId);
        assertEquals(409, revoke.getResponse().getStatus());
        assertEquals("ACTIVE_KEY_REVOKE_FORBIDDEN", errorCode(revoke));

        // 活跃密钥仍正常签发与校验
        MvcResult stillOk = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        assertEquals(200, stillOk.getResponse().getStatus());
    }

    @Test
    @DisplayName("轮换过程中并发读取同一凭证，校验结论始终一致，不出现时好时坏")
    void concurrentVerificationStableAcrossRotation() throws Exception {
        TokenPair before = loginAlice();
        int rounds = 200;
        java.util.Set<Integer> statuses = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
        java.util.List<Thread> threads = new java.util.ArrayList<>();
        threads.add(new Thread(() -> {
            for (int i = 0; i < rounds; i++) {
                try {
                    rotateKey();
                } catch (Exception ignored) {
                    // 轮换接口在测试中不会失败
                }
            }
        }));
        for (int t = 0; t < 4; t++) {
            threads.add(new Thread(() -> {
                for (int i = 0; i < rounds; i++) {
                    try {
                        MvcResult result = getResource("/api/resources/read",
                                "Bearer " + before.accessToken());
                        statuses.add(result.getResponse().getStatus());
                    } catch (Exception ignored) {
                        // 仅统计已完成的响应
                    }
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread thread : threads) {
            thread.join(30000);
        }
        // 时间未推进，所有被轮换下去的旧密钥都仍处于宽限期内，因此必须全程 200。
        assertEquals(java.util.Set.of(200), statuses,
                "宽限期内的轮换不得让既有凭证校验结果出现波动");
    }

    @Test
    @DisplayName("密钥列表能区分 ACTIVE、GRACE、EXPIRED、REVOKED 四种状态")
    void keyListReportsDistinctStatuses() throws Exception {
        TokenPair alice = loginAlice();
        MvcResult access = getResource("/api/resources/read", "Bearer " + alice.accessToken());
        String firstKeyId = JSON.readTree(access.getResponse().getContentAsString())
                .get("keyId").asText();
        MvcResult rotate = rotateKey();
        String secondKeyId = JSON.readTree(rotate.getResponse().getContentAsString())
                .get("activeKeyId").asText();
        MvcResult rotateAgain = rotateKey();
        String thirdKeyId = JSON.readTree(rotateAgain.getResponse().getContentAsString())
                .get("activeKeyId").asText();
        assertEquals(200, revokeKey(secondKeyId).getResponse().getStatus());
        MvcResult list = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/api/keys")).andReturn();
        JsonNode keys = JSON.readTree(list.getResponse().getContentAsString());
        assertEquals("GRACE", statusOf(keys, firstKeyId));
        assertEquals("REVOKED", statusOf(keys, secondKeyId));
        assertEquals("ACTIVE", statusOf(keys, thirdKeyId));

        timeSource.advanceHours(25);
        MvcResult expiredList = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/api/keys")).andReturn();
        JsonNode expiredKeys = JSON.readTree(expiredList.getResponse().getContentAsString());
        assertEquals("EXPIRED", statusOf(expiredKeys, firstKeyId));
        assertEquals("REVOKED", statusOf(expiredKeys, secondKeyId));
        assertEquals("ACTIVE", statusOf(expiredKeys, thirdKeyId));
    }

    private String statusOf(JsonNode keys, String keyId) {
        for (JsonNode key : keys) {
            if (keyId.equals(key.get("keyId").asText())) {
                return key.get("status").asText();
            }
        }
        return null;
    }
}
