package io.contexa.contexacore.config.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.time.Duration;


public class CustomDurationDeserializer extends JsonDeserializer<Duration> {

    @Override
    public Duration deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getText();
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        value = value.trim();

        
        if (value.startsWith("P")) {
            try {
                return Duration.parse(value);
            } catch (Exception e) {
                
            }
        }

        
        if (value.matches("\\d{2}:\\d{2}:\\d{2}")) {
            String[] parts = value.split(":");
            long hours = Long.parseLong(parts[0]);
            long minutes = Long.parseLong(parts[1]);
            long seconds = Long.parseLong(parts[2]);
            return Duration.ofHours(hours)
                    .plusMinutes(minutes)
                    .plusSeconds(seconds);
        }

        
        try {
            long millis = Long.parseLong(value);
            return Duration.ofMillis(millis);
        } catch (NumberFormatException e) {
            
        }

        
        return Duration.ZERO;
    }
}