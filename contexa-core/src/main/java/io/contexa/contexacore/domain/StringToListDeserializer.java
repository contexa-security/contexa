package io.contexa.contexacore.domain;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * String "[]" 또는 실제 배열을 List<String>으로 변환하는 디시리얼라이저
 */
public class StringToListDeserializer extends JsonDeserializer<List<String>> {

    @Override
    public List<String> deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JsonProcessingException {

        JsonNode node = p.getCodec().readTree(p);
        List<String> result = new ArrayList<>();

        if (node.isArray()) {
            // 정상적인 배열인 경우
            for (JsonNode element : node) {
                result.add(element.asText());
            }
        } else if (node.isTextual()) {
            // 문자열인 경우 ("[]" 등)
            String value = node.asText();
            if ("[]".equals(value) || value.isEmpty()) {
                // 빈 리스트 반환
                return result;
            }
            // 그 외의 문자열은 단일 요소로 추가
            result.add(value);
        }

        return result;
    }
}