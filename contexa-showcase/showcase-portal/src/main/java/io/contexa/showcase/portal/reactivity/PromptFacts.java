package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * W6-1 (P6-CHANGE-2): the facts of a sealed prompt as the harness compares them: label to the values of its lines, as
 * control D read them with the OSS prompt parser ({@code /internal/decisions/{requestId}/prompt-facts}). Run identity
 * inside a value (UUIDs, run hex ids, the host part of the run's address) becomes a placeholder, so two runs of the same
 * facts compare equal (plan 8.6; the prototype's normalise in prompt-audit/w06/delivery.py).
 */
public record PromptFacts(Map<String, List<String>> values) {

    private static final Pattern UUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern RUN = Pattern.compile("(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])");
    private static final Pattern HOST = Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}\\b");

    public PromptFacts {
        values = Map.copyOf(values);
    }

    public static PromptFacts of(JsonNode promptFacts) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        for (JsonNode line : promptFacts.path("lines")) {
            String label = line.path("label").asText(null);
            if (label == null) {
                continue;
            }
            values.computeIfAbsent(label, key -> new ArrayList<>()).add(normalise(line.path("value").asText("")));
        }
        Map<String, List<String>> fixed = new LinkedHashMap<>();
        values.forEach((label, list) -> fixed.put(label, List.copyOf(list)));
        return new PromptFacts(fixed);
    }

    static String normalise(String value) {
        String text = UUID.matcher(value).replaceAll("<uuid>");
        text = RUN.matcher(text).replaceAll("<run>");
        return HOST.matcher(text).replaceAll("$1.<host>");
    }
}
