package io.contexa.contexaiam.admin.promptquality.official.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Parses and normalizes raw values used by official console views. */
final class PromptQualityOfficialViewValueReader {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");

    private PromptQualityOfficialViewValueReader() {
    }

    static Instant parseInstant(String value, Instant fallback) {
        if (!StringUtils.hasText(value)) {
            return fallback;
        }
        String normalized = value.trim();
        try {
            return Instant.parse(normalized);
        }
        catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(normalized).atZone(KOREA_ZONE).toInstant();
            }
            catch (DateTimeParseException ignoredAgain) {
                try {
                    return LocalDate.parse(normalized).atStartOfDay(KOREA_ZONE).toInstant();
                }
                catch (DateTimeParseException finalIgnored) {
                    return fallback;
                }
            }
        }
    }

    static Object objectValue(ObjectMapper objectMapper, String raw) {
        JsonNode node = json(objectMapper, raw);
        return objectMapper.convertValue(node, Object.class);
    }

    static JsonNode json(ObjectMapper objectMapper, String raw) {
        if (!StringUtils.hasText(raw)) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(raw);
        }
        catch (Exception ignored) {
            return objectMapper.createObjectNode();
        }
    }

    static String firstJsonText(JsonNode root, String... names) {
        Set<String> wanted = new LinkedHashSet<>();
        for (String name : names) {
            wanted.add(name.toLowerCase(Locale.ROOT));
        }
        JsonNode found = find(root, wanted);
        if (found == null || found.isMissingNode() || found.isNull()) {
            return "";
        }
        return found.isValueNode() ? found.asText("") : found.toString();
    }

    private static JsonNode find(JsonNode node, Set<String> names) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                if (names.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                    return entry.getValue();
                }
                JsonNode nested = find(entry.getValue(), names);
                if (nested != null) {
                    return nested;
                }
            }
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                JsonNode nested = find(child, names);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    static String preview(String value) {
        String text = string(value);
        if (text.length() <= 4000) {
            return text;
        }
        return text.substring(0, 4000);
    }

    static String iso(Instant instant) {
        return instant == null ? "" : instant.toString();
    }

    static String stringValue(Map<String, Object> body, String key) {
        return body == null ? "" : string(body.get(key));
    }

    static String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    static String string(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }
}