package com.github.lechandonga.tokenrotationaccesscontroljava.tests.support;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** 测试 HTTP 辅助：封装登录/刷新/带凭证访问。 */
public class ApiClient {

    private final TestRestTemplate rest;

    public ApiClient(TestRestTemplate rest) {
        this.rest = rest;
    }

    public JsonNode login(String subjectId) {
        return postForJson("/auth/login", "{\"subjectId\":\"" + subjectId + "\"}", null).getBody();
    }

    public ResponseEntity<JsonNode> refreshRaw(String refreshToken) {
        return postForJson("/auth/refresh", "{\"refreshToken\":\"" + refreshToken + "\"}", null);
    }

    public JsonNode refresh(String refreshToken) {
        return refreshRaw(refreshToken).getBody();
    }

    public ResponseEntity<JsonNode> get(String path, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers), JsonNode.class);
    }

    public ResponseEntity<JsonNode> post(String path, String bodyJson, String accessToken) {
        return postForJson(path, bodyJson, accessToken);
    }

    private ResponseEntity<JsonNode> postForJson(String path, String bodyJson, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (accessToken != null) {
            headers.setBearerAuth(accessToken);
        }
        return rest.exchange(path, HttpMethod.POST,
                new HttpEntity<>(bodyJson, headers), JsonNode.class);
    }

    public static String errorCode(ResponseEntity<JsonNode> response) {
        JsonNode body = response.getBody();
        return body != null && body.has("code") ? body.get("code").asText() : "<no-code>";
    }
}
