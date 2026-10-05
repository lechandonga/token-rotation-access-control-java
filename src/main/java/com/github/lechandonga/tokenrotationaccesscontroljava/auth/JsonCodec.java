package com.github.lechandonga.tokenrotationaccesscontroljava.auth;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 复用 Spring Boot 自带 Jackson 的极简 JSON 工具。
 */
final class JsonCodec {

    static class JsonException extends RuntimeException {
        JsonException(Throwable cause) {
            super(cause);
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonCodec() {
    }

    static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new JsonException(e);
        }
    }

    static <T> T fromJson(String json, Class<T> type) {
        try {
            return MAPPER.readValue(json, type);
        } catch (Exception e) {
            throw new JsonException(e);
        }
    }
}
