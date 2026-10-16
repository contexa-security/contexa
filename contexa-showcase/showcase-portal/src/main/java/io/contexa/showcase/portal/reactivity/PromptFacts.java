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
 * facts compare equal (plan 8.6; the prototype's normalise in prompt-audit/w06/delivery.py). N-DLV-2: the kinds of
 * company record the host looked up for the request and the request's action family, as control D read them from the
 * sealed context ({@code checkedRecordKinds}, {@code actionFamily}); null when the seal does not say.
 */
public record PromptFacts(Map<String, List<String>> values, List<String> checkedRecordKinds, String actionFamily) {

    private static final Pattern UUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern RUN = Pattern.compile("(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])");
    private static final Pattern HOST = Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}\\b");

    public PromptFacts {
        values = Map.copyOf(values);
        checkedRecordKinds = checkedRecordKinds == null ? null : List.copyOf(checkedRecordKinds);
    }

    /** Facts of a seal that does not say what was looked up. */
    public PromptFacts(Map<String, List<String>> values) {
        this(values, null, null);
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
        // N-DLV-2: what the host looked up and the request's action family, when control D gives them.
        List<String> checked = null;
        if (promptFacts.path("checkedRecordKinds").isArray()) {
            checked = new ArrayList<>();
            for (JsonNode kind : promptFacts.path("checkedRecordKinds")) {
                checked.add(kind.asText());
            }
        }
        JsonNode family = promptFacts.path("actionFamily");
        return new PromptFacts(fixed, checked, family.isTextual() ? family.asText() : null);
    }

    static String normalise(String value) {
        String text = UUID.matcher(value).replaceAll("<uuid>");
        text = RUN.matcher(text).replaceAll("<run>");
        return HOST.matcher(text).replaceAll("$1.<host>");
    }
}
