package io.contexa.contexacommon.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * LocalDateTime에 대한 null-safe 역직렬화 처리
 *
 * LLM이 잘못된 형식으로 날짜를 반환하는 경우를 안전하게 처리합니다.
 * - "None", "null", 빈 문자열 → null 반환
 * - 유효한 ISO 형식 → LocalDateTime 파싱
 * - 잘못된 형식 → null 반환 (예외 발생 방지)
 */
public class NullSafeLocalDateTimeDeserializer extends JsonDeserializer<LocalDateTime> {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Override
    public LocalDateTime deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getText();

        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        String normalized = value.trim();

        if ("None".equalsIgnoreCase(normalized) ||
            "null".equalsIgnoreCase(normalized) ||
            "undefined".equalsIgnoreCase(normalized)) {
            return null;
        }

        try {
            return LocalDateTime.parse(normalized, ISO_FORMATTER);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}