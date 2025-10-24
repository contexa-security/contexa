package io.contexa.contexacore.config.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.time.Duration;

/**
 * Custom Duration deserializer to handle various time formats
 * Supports:
 * - ISO-8601 duration format: PT0S, P1DT2H3M4S
 * - Time format: HH:MM:SS (e.g., "00:00:00", "01:30:45")
 */
public class CustomDurationDeserializer extends JsonDeserializer<Duration> {

    @Override
    public Duration deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getText();
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        value = value.trim();

        // Try ISO-8601 format first (PT0S, P1DT2H3M4S, etc.)
        if (value.startsWith("P")) {
            try {
                return Duration.parse(value);
            } catch (Exception e) {
                // Fall through to try other formats
            }
        }

        // Try HH:MM:SS format
        if (value.matches("\\d{2}:\\d{2}:\\d{2}")) {
            String[] parts = value.split(":");
            long hours = Long.parseLong(parts[0]);
            long minutes = Long.parseLong(parts[1]);
            long seconds = Long.parseLong(parts[2]);
            return Duration.ofHours(hours)
                    .plusMinutes(minutes)
                    .plusSeconds(seconds);
        }

        // Try as milliseconds if it's a number
        try {
            long millis = Long.parseLong(value);
            return Duration.ofMillis(millis);
        } catch (NumberFormatException e) {
            // Not a number, continue
        }

        // Default to empty duration if format is unrecognized
        return Duration.ZERO;
    }
}