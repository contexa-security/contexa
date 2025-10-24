package io.contexa.contexacore.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Converter
public class JpaListConverter implements AttributeConverter<List<?>, String> {

    private static final Logger logger = LoggerFactory.getLogger(JpaListConverter.class);
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Override
    public String convertToDatabaseColumn(List<?> attribute) {
        if (attribute == null || attribute.isEmpty()) {
            return "[]";
        }
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            logger.error("Error converting list to JSON string", e);
            throw new IllegalArgumentException("Could not convert list to JSON", e);
        }
    }

    @Override
    public List<?> convertToEntityAttribute(String dbData) {
        if (!StringUtils.hasText(dbData)) {
            return Collections.emptyList();
        }
        try {
            return objectMapper.readValue(dbData, new TypeReference<List<?>>() {});
        } catch (IOException e) {
            logger.error("Error converting JSON string to list", e);
            throw new IllegalArgumentException("Could not convert JSON to list", e);
        }
    }
}
