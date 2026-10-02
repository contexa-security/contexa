package io.contexa.demo.observation.provider.service.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.contexa.contexacore.util.SensitiveValueSanitizer;
import io.contexa.demo.observation.provider.service.ProviderBodySanitizer;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Component
@Profile("contexa")
public class JsonProviderBodySanitizer implements ProviderBodySanitizer {

    private static final Set<String> SECRET_KEYS = Set.of("password", "credential", "credentials", "cookie",
            "set-cookie", "authorization", "token", "access_token", "refresh_token", "api_key", "apikey",
            "secret", "sessionid", "session_id", "sessiontoken", "verificationcode", "otp", "pin");
    private static final Pattern SESSION_VALUE = Pattern.compile("\\b[A-Fa-f0-9]{32}\\b");
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)((?:password|cookie|session[_-]?id|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|otp|pin|verification[_-]?code)"
                    + "[\\\"']?\\s*[:=]\\s*[\\\"']?)([^\\s,\\\"'};]+)");
    private final ObjectMapper mapper;

    public JsonProviderBodySanitizer(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String sanitize(byte[] body) {
        try {
            JsonNode parsed = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(body);
            if (parsed == null || !parsed.isObject()) {
                return null;
            }
            return mapper.writeValueAsString(redact(parsed));
        } catch (IOException invalidJson) {
            return null;
        }
    }

    private JsonNode redact(JsonNode node) {
        if (node.isObject()) {
            ObjectNode safe = mapper.createObjectNode();
            node.fields().forEachRemaining(entry -> safe.set(entry.getKey(),
                    SECRET_KEYS.contains(entry.getKey().toLowerCase(Locale.ROOT))
                            ? TextNode.valueOf("[REDACTED]") : redact(entry.getValue())));
            return safe;
        }
        if (node.isArray()) {
            ArrayNode safe = mapper.createArrayNode();
            node.forEach(value -> safe.add(redact(value)));
            return safe;
        }
        if (node.isTextual()) {
            String safe = SensitiveValueSanitizer.sanitizeText(node.textValue());
            safe = SESSION_VALUE.matcher(safe).replaceAll("[REDACTED_SESSION_ID]");
            return TextNode.valueOf(ASSIGNMENT.matcher(safe).replaceAll("$1[REDACTED]"));
        }
        return node;
    }
}
