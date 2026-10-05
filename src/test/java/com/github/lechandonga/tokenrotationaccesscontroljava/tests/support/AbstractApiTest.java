package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 接口测试基类：统一上下文、可控时间源与登录/刷新辅助方法。
 */
@SpringBootTest(classes = {
        com.github.lechandonga.tokenrotationaccesscontroljava.Application.class,
        TestAuthConfiguration.class
})
@AutoConfigureMockMvc
public abstract class AbstractApiTest {

    protected static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ApplicationContext applicationContext;

    @Autowired
    protected ControllableTimeSource timeSource;

    @BeforeEach
    void resetVirtualClock() {
        timeSource.reset();
    }

    protected record TokenPair(String accessToken, String refreshToken, String familyId) {
    }

    protected TokenPair login(String subjectId, String secret) throws Exception {
        String body = "{\"subjectId\":\"" + subjectId + "\",\"secret\":\"" + secret + "\"}";
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json").content(body))
                .andReturn();
        JsonNode json = JSON.readTree(result.getResponse().getContentAsString());
        return new TokenPair(json.get("accessToken").asText(),
                json.get("refreshToken").asText(),
                json.get("familyId").asText());
    }

    protected TokenPair loginAlice() throws Exception {
        return login("alice", "alice-secret");
    }

    protected TokenPair loginBob() throws Exception {
        return login("bob", "bob-secret");
    }

    protected MvcResult refresh(String refreshToken) throws Exception {
        return performRefresh(mockMvc, refreshToken);
    }

    /**
     * 使用独立 MockMvc 执行刷新；默认 MockMvc 非线程安全，
     * 并发测试中每个工作线程应各自构建，避免不确定结果。
     */
    protected MvcResult refreshOnStandaloneMvc(String refreshToken) throws Exception {
        MockMvc standalone = MockMvcBuilders
                .webAppContextSetup((WebApplicationContext) applicationContext).build();
        return performRefresh(standalone, refreshToken);
    }

    private MvcResult performRefresh(MockMvc mvc, String refreshToken) throws Exception {
        return mvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andReturn();
    }

    protected TokenPair refreshAndParse(String refreshToken) throws Exception {
        MvcResult result = refresh(refreshToken);
        JsonNode json = JSON.readTree(result.getResponse().getContentAsString());
        return new TokenPair(json.get("accessToken").asText(),
                json.get("refreshToken").asText(),
                json.get("familyId").asText());
    }

    protected MvcResult getResource(String path, String authorization) throws Exception {
        var requestBuilder = get(path);
        if (authorization != null) {
            requestBuilder.header("Authorization", authorization);
        }
        return mockMvc.perform(requestBuilder).andReturn();
    }

    protected MvcResult rotateKey() throws Exception {
        return mockMvc.perform(post("/api/keys/rotate")).andReturn();
    }

    protected MvcResult revokeKey(String keyId) throws Exception {
        return mockMvc.perform(post("/api/keys/" + keyId + "/revoke")).andReturn();
    }

    protected String errorCode(MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString()).get("error").asText();
    }
}
