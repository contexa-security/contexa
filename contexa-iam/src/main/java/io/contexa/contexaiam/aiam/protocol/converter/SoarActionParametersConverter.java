package io.contexa.contexaiam.aiam.protocol.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
@Converter
public class SoarActionParametersConverter implements AttributeConverter<Map<String, Object>, String> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(Map<String, Object> attribute) {
        if (attribute == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            log.error("Error converting map to JSON string", e);
            return null; // 또는 예외를 다시 던질 수 있습니다.
        }
    }

    @Override
    public Map<String, Object> convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }
        try {
            return objectMapper.readValue(dbData, Map.class);
        } catch (JsonProcessingException e) {
            log.error("Error converting JSON string to map", e);
            return null; // 또는 예외를 다시 던질 수 있습니다.
        }
    }

    // SoarAction에서 직접 호출할 수 있도록 static 헬퍼 메서드 추가
    public static String toJson(Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            log.error("Error converting map to JSON string", e);
            throw new RuntimeException("Failed to convert map to JSON string", e);
        }
    }

    public static Map<String, Object> toMap(String json) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            log.error("Error converting JSON string to map", e);
            throw new RuntimeException("Failed to convert JSON string to map", e);
        }
    }
}
