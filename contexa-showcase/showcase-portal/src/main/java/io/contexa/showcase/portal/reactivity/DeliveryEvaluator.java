package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * W6-1 (P6-CHANGE-2, plan 8.4, metric C4): the delivery check. A run that changes one lab condition is compared fact by
 * fact with the designed run of the same case; the facts the condition should change are listed per condition (plan
 * 8.4, resource reactivity/delivery-expected.json, the v20 column of the prototype prompt-audit/w06/delivery.py), and
 * the lines that differ in every run by construction are left out. A condition is delivered when only expected facts
 * changed and at least one did; the invariance condition is delivered when nothing but its expected facts changed.
 * With the requested value, the changed line must also say that value (plan 8.4: the changed value equals the case
 * definition), by the value patterns of the same resource, written from the renderer's wording.
 */
public final class DeliveryEvaluator {

    static final String INVARIANT = "invariant";

    private final Map<String, List<Pattern>> expected;
    private final Pattern volatileLabels;
    private final Map<String, Map<String, ValueCheck>> values;

    DeliveryEvaluator(Map<String, List<Pattern>> expected, Pattern volatileLabels,
                      Map<String, Map<String, ValueCheck>> values) {
        this.expected = Map.copyOf(expected);
        this.volatileLabels = Objects.requireNonNull(volatileLabels, "volatileLabels");
        this.values = Map.copyOf(values);
    }

    /**
     * The changed facts, those the condition should change, those it should not have changed, and whether the changed
     * line says the requested value (null when no value was requested or the resource has no pattern for it). W7-13:
     * how many lines of the variant were compared and did not change, the volatile lines left out as for the changes.
     */
    public record Delivery(List<String> changed, List<String> delivered, List<String> unexpected, Boolean valueMatches,
                           boolean passed, int unchangedLines) {
    }

    /**
     * The line that must say a requested value, and its pattern; {@code {value}} stands for the quoted value and
     * {@code {number}} for the value as the renderer writes numbers. A negated check holds when no value of the line
     * matches, also when the line is absent.
     */
    record ValueCheck(String line, String pattern, boolean negate) {
    }

    public static DeliveryEvaluator fromResources() {
        try (InputStream stream = DeliveryEvaluator.class.getResourceAsStream("/reactivity/delivery-expected.json")) {
            if (stream == null) {
                throw new IllegalStateException("reactivity/delivery-expected.json is missing");
            }
            JsonNode root = new ObjectMapper().readTree(stream);
            Map<String, List<Pattern>> expected = new LinkedHashMap<>();
            root.path("expected").fields().forEachRemaining(entry -> {
                List<Pattern> patterns = new ArrayList<>();
                entry.getValue().forEach(label -> patterns.add(wildcard(label.asText())));
                expected.put(entry.getKey(), List.copyOf(patterns));
            });
            List<String> volatileNames = new ArrayList<>();
            root.path("volatile").forEach(name -> volatileNames.add(name.asText()));
            Map<String, Map<String, ValueCheck>> values = new LinkedHashMap<>();
            root.path("values").fields().forEachRemaining(condition -> {
                Map<String, ValueCheck> checks = new LinkedHashMap<>();
                condition.getValue().fields().forEachRemaining(value -> {
                    JsonNode check = value.getValue();
                    checks.put(value.getKey().toLowerCase(Locale.ROOT), new ValueCheck(check.path("line").asText(),
                            check.path("pattern").asText(), check.path("negate").asBoolean(false)));
                });
                values.put(condition.getKey(), Map.copyOf(checks));
            });
            return new DeliveryEvaluator(expected, Pattern.compile("^(" + String.join("|", volatileNames) + ")$"),
                    values);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Delivery compare(PromptFacts base, PromptFacts variant, String condition) {
        return compare(base, variant, condition, null);
    }

    public Delivery compare(PromptFacts base, PromptFacts variant, String condition, String value) {
        List<Pattern> labels = expected.get(condition);
        if (labels == null) {
            throw new IllegalArgumentException("Unknown lab condition: " + condition);
        }
        Set<String> names = new TreeSet<>();
        names.addAll(base.values().keySet());
        names.addAll(variant.values().keySet());
        List<String> changed = new ArrayList<>();
        int unchangedLines = 0;
        for (String name : names) {
            if (volatileLabels.matcher(name).matches()) {
                continue;
            }
            if (Objects.equals(base.values().get(name), variant.values().get(name))) {
                unchangedLines += variant.values().get(name).size();
            } else {
                changed.add(name);
            }
        }
        Set<String> delivered = new LinkedHashSet<>();
        List<String> unexpected = new ArrayList<>();
        for (String name : changed) {
            if (labels.stream().anyMatch(pattern -> pattern.matcher(name).matches())) {
                delivered.add(name);
            } else {
                unexpected.add(name);
            }
        }
        Boolean valueMatches = valueMatches(variant, condition, value);
        boolean passed = unexpected.isEmpty() && (INVARIANT.equals(condition) || !delivered.isEmpty())
                && !Boolean.FALSE.equals(valueMatches);
        return new Delivery(List.copyOf(changed), List.copyOf(delivered), List.copyOf(unexpected), valueMatches,
                passed, unchangedLines);
    }

    private Boolean valueMatches(PromptFacts variant, String condition, String value) {
        if (value == null) {
            return null;
        }
        Map<String, ValueCheck> checks = values.getOrDefault(condition, Map.of());
        ValueCheck check = checks.getOrDefault(value.toLowerCase(Locale.ROOT), checks.get("*"));
        if (check == null) {
            return null;
        }
        Pattern pattern = Pattern.compile(check.pattern().replace("{value}", Pattern.quote(value))
                .replace("{number}", Pattern.quote(number(value))));
        boolean found = variant.values().getOrDefault(check.line(), List.of()).stream()
                .anyMatch(line -> pattern.matcher(line).find());
        return check.negate() != found;
    }

    /** The value as the renderer writes a count (4831 becomes 4,831); other values unchanged. */
    private static String number(String value) {
        try {
            return String.format(Locale.ROOT, "%,d", Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            return value;
        }
    }

    private static Pattern wildcard(String label) {
        return Pattern.compile(Pattern.quote(label).replace("*", "\\E.*\\Q"));
    }
}
