package io.contexa.contexacommon.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;


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