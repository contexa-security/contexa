package io.contexa.contexacore.domain;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


public class StringToListDeserializer extends JsonDeserializer<List<String>> {

    @Override
    public List<String> deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JsonProcessingException {

        JsonNode node = p.getCodec().readTree(p);
        List<String> result = new ArrayList<>();

        if (node.isArray()) {
            
            for (JsonNode element : node) {
                result.add(element.asText());
            }
        } else if (node.isTextual()) {
            
            String value = node.asText();
            if ("[]".equals(value) || value.isEmpty()) {
                
                return result;
            }
            
            result.add(value);
        }

        return result;
    }
}