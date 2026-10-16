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
 * definition), by the value patterns of the same resource, written from the renderer's wording. N-DLV-2: a condition
 * whose need the base run's seal shows unmet (resource 'applies': a record kind not looked up, an action family that
 * does not read the claim) cannot reach the prompt, so it is compared as the invariance condition. N-DLV-5: from
 * the second step on, the facts that follow the run's earlier steps may change too, and only the first step must
 * deliver an expected fact and say the requested value.
 */
public final class DeliveryEvaluator {

    static final String INVARIANT = "invariant";
    /** N-DLV-5: the key of the resource's later-step facts that follow every condition. */
    static final String ANY_CONDITION = "*";

    private final Map<String, List<Pattern>> expected;
    private final Map<String, List<Pattern>> derived;
    private final Map<String, Applies> applies;
    private final Map<String, List<Pattern>> laterSteps;
    private final Pattern volatileLabels;
    private final Map<String, Map<String, ValueCheck>> values;

    DeliveryEvaluator(Map<String, List<Pattern>> expected, Pattern volatileLabels,
                      Map<String, Map<String, ValueCheck>> values) {
        this(expected, Map.of(), volatileLabels, values);
    }

    /**
     * P7-CHANGE-9: with the facts each condition changes by definition (resource 'derived', each with its reason),
     * which may change without being required to.
     */
    DeliveryEvaluator(Map<String, List<Pattern>> expected, Map<String, List<Pattern>> derived, Pattern volatileLabels,
                      Map<String, Map<String, ValueCheck>> values) {
        this(expected, derived, Map.of(), Map.of(), volatileLabels, values);
    }

    /**
     * N-DLV-2: with what each condition needs to reach the prompt (resource 'applies', with its reason). N-DLV-5: and
     * the facts that may change from the second step on (resource 'laterSteps', by condition or for every one).
     */
    DeliveryEvaluator(Map<String, List<Pattern>> expected, Map<String, List<Pattern>> derived,
                      Map<String, Applies> applies, Map<String, List<Pattern>> laterSteps, Pattern volatileLabels,
                      Map<String, Map<String, ValueCheck>> values) {
        this.expected = Map.copyOf(expected);
        this.derived = Map.copyOf(derived);
        this.applies = Map.copyOf(applies);
        this.laterSteps = Map.copyOf(laterSteps);
        this.volatileLabels = Objects.requireNonNull(volatileLabels, "volatileLabels");
        this.values = Map.copyOf(values);
    }

    /**
     * The changed facts, those the condition should change, those it should not have changed, and whether the changed
     * line says the requested value (null when no value was requested or the resource has no pattern for it). W7-13:
     * how many lines of the variant were compared and did not change, the volatile lines left out as for the changes.
     * N-DLV-2: what the base run's operation did not look up for the condition (its record kind or CLAIMED_TICKET),
     * the comparison then being the invariance one; null when the condition applies or the seal does not say.
     */
    public record Delivery(List<String> changed, List<String> delivered, List<String> unexpected, Boolean valueMatches,
                           boolean passed, int unchangedLines, List<String> derived, String notLookedUp) {

        /** P7-CHANGE-9: a delivery without derived facts. */
        public Delivery(List<String> changed, List<String> delivered, List<String> unexpected, Boolean valueMatches,
                        boolean passed, int unchangedLines) {
            this(changed, delivered, unexpected, valueMatches, passed, unchangedLines, List.of(), null);
        }
    }

    /**
     * The line that must say a requested value, and its pattern; {@code {value}} stands for the quoted value and
     * {@code {number}} for the value as the renderer writes numbers. A negated check holds when no value of the line
     * matches, also when the line is absent.
     */
    record ValueCheck(String line, String pattern, boolean negate) {
    }

    /**
     * N-DLV-2: what a condition needs to reach the prompt: its kind of company record among the kinds the host looked
     * up, or one of the action families that read it; lookup names what is not looked up otherwise.
     */
    record Applies(String recordKind, List<String> actionFamilies, String lookup) {
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
            Map<String, List<Pattern>> derived = new LinkedHashMap<>();
            root.path("derived").fields().forEachRemaining(entry -> {
                List<Pattern> patterns = new ArrayList<>();
                entry.getValue().path("facts").forEach(label -> patterns.add(wildcard(label.asText())));
                derived.put(entry.getKey(), List.copyOf(patterns));
            });
            Map<String, Applies> applies = new LinkedHashMap<>();
            root.path("applies").path("conditions").fields().forEachRemaining(entry -> {
                List<String> families = new ArrayList<>();
                entry.getValue().path("actionFamilies").forEach(family -> families.add(family.asText()));
                applies.put(entry.getKey(), new Applies(entry.getValue().path("recordKind").asText(null),
                        List.copyOf(families), entry.getValue().path("lookup").asText(null)));
            });
            Map<String, List<Pattern>> laterSteps = new LinkedHashMap<>();
            root.path("laterSteps").fields().forEachRemaining(entry -> {
                List<Pattern> patterns = new ArrayList<>();
                entry.getValue().path("facts").forEach(label -> patterns.add(wildcard(label.asText())));
                laterSteps.put(entry.getKey(), List.copyOf(patterns));
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
            return new DeliveryEvaluator(expected, derived, applies, laterSteps,
                    Pattern.compile("^(" + String.join("|", volatileNames) + ")$"), values);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Delivery compare(PromptFacts base, PromptFacts variant, String condition) {
        return compare(base, variant, condition, null);
    }

    public Delivery compare(PromptFacts base, PromptFacts variant, String condition, String value) {
        return compare(base, variant, condition, value, 1);
    }

    /**
     * N-DLV-5: the comparison of the runs' step of the given number. From the second step on, the facts that follow
     * the run's earlier steps may change too (resource 'laterSteps', by condition or for every one), and only the first
     * step must deliver an expected fact and say the requested value.
     */
    public Delivery compare(PromptFacts base, PromptFacts variant, String condition, String value, int stepNo) {
        if (!expected.containsKey(condition)) {
            throw new IllegalArgumentException("Unknown lab condition: " + condition);
        }
        // N-DLV-2: a condition the base run's operation does not look up cannot reach the prompt; it is compared as
        // the invariance condition. A seal that does not say what was looked up is compared as before.
        String notLookedUp = notLookedUp(base, condition);
        String compared = notLookedUp != null ? INVARIANT : condition;
        List<Pattern> labels = expected.get(compared);
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
        // N-DLV-5: from the second step on, the facts that follow the run's earlier steps may change too, looked up by
        // the run's own condition.
        boolean later = stepNo > 1;
        List<Pattern> following = new ArrayList<>(derived.getOrDefault(compared, List.of()));
        if (later) {
            following.addAll(laterSteps.getOrDefault(ANY_CONDITION, List.of()));
            following.addAll(laterSteps.getOrDefault(condition, List.of()));
        }
        Set<String> delivered = new LinkedHashSet<>();
        List<String> derivedChanges = new ArrayList<>();
        List<String> unexpected = new ArrayList<>();
        for (String name : changed) {
            if (labels.stream().anyMatch(pattern -> pattern.matcher(name).matches())) {
                delivered.add(name);
            } else if (following.stream().anyMatch(pattern -> pattern.matcher(name).matches())) {
                derivedChanges.add(name);
            } else {
                unexpected.add(name);
            }
        }
        Boolean valueMatches = notLookedUp != null || later ? null : valueMatches(variant, condition, value);
        boolean passed = unexpected.isEmpty() && (INVARIANT.equals(compared) || later || !delivered.isEmpty())
                && !Boolean.FALSE.equals(valueMatches);
        return new Delivery(List.copyOf(changed), List.copyOf(delivered), List.copyOf(unexpected), valueMatches,
                passed, unchangedLines,
                List.copyOf(derivedChanges), notLookedUp);
    }

    /** What the base run's operation did not look up for the condition (N-DLV-2); null when it did or is not known. */
    private String notLookedUp(PromptFacts base, String condition) {
        Applies needs = applies.get(condition);
        if (needs == null) {
            return null;
        }
        if (needs.recordKind() != null && base.checkedRecordKinds() != null
                && base.checkedRecordKinds().stream().noneMatch(needs.recordKind()::equalsIgnoreCase)) {
            return needs.recordKind();
        }
        if (!needs.actionFamilies().isEmpty() && base.actionFamily() != null
                && needs.actionFamilies().stream().noneMatch(base.actionFamily()::equalsIgnoreCase)) {
            return needs.lookup() != null ? needs.lookup() : condition;
        }
        return null;
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
