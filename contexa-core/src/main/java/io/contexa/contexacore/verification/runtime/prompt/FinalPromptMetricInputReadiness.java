package io.contexa.contexacore.verification.runtime.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

record FinalPromptMetricInputReadiness(
        boolean ready,
        List<String> missingInputs,
        List<String> presentInputs
) {

    static FinalPromptMetricInputReadiness allReady() {
        return new FinalPromptMetricInputReadiness(true, List.of(), List.of());
    }

    static FinalPromptMetricInputReadiness evaluate(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        return evaluate(rule, context == null ? null : context.prompt());
    }

    private static FinalPromptMetricInputReadiness evaluate(
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt) {
        if (rule == null || !StringUtils.hasText(rule.operator())) {
            return allReady();
        }
        return switch (normalize(rule.operator())) {
            case "ALL" -> all(rule.all(), prompt);
            case "ANY" -> any(rule.any(), prompt);
            case "SECTIONS_DECIDABLE" -> requireSections(prompt, rule.sections());
            case "FIELDS_DECIDABLE" -> requireAllLabels(prompt, rule.labels());
            case "ANY_FIELD_DECIDABLE" -> requireAnyLabel(prompt, rule.labels());
            case "MIN_FIELDS_DECIDABLE" -> requireMinLabels(prompt, rule.labels(), safeMin(rule.minCount()));
            case "FIELD_VALUES_CONSISTENT", "BOOLEAN_FIELDS_CONSISTENT" -> requireAnyLabel(prompt, rule.labels());
            case "IF_FIELD_EQUALS_THEN_FORBIDDEN_TERMS_ABSENT" -> requireAnyLabel(prompt, List.of(rule.field()));
            case "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT" -> requireThenInputsWhenTriggered(prompt, rule);
            default -> allReady();
        };
    }

    private static FinalPromptMetricInputReadiness all(List<FinalPromptMetricRule> rules, FinalPromptSnapshot prompt) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (FinalPromptMetricRule child : rules) {
            FinalPromptMetricInputReadiness childReadiness = evaluate(child, prompt);
            missing.addAll(childReadiness.missingInputs());
            present.addAll(childReadiness.presentInputs());
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness any(List<FinalPromptMetricRule> rules, FinalPromptSnapshot prompt) {
        if (rules == null || rules.isEmpty()) {
            return allReady();
        }
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (FinalPromptMetricRule child : rules) {
            FinalPromptMetricInputReadiness childReadiness = evaluate(child, prompt);
            if (childReadiness.ready()) {
                return childReadiness;
            }
            missing.addAll(childReadiness.missingInputs());
            present.addAll(childReadiness.presentInputs());
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness requireSections(
            FinalPromptSnapshot prompt,
            List<String> sections) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (String section : sections) {
            if (!StringUtils.hasText(section)) {
                continue;
            }
            if (prompt != null && prompt.hasSection(section)) {
                present.add("section:" + section);
            }
            else if (absenceExplained(prompt, section)) {
                present.add("explainedAbsence:section:" + section);
            }
            else {
                missing.add("section:" + section);
            }
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness requireAllLabels(
            FinalPromptSnapshot prompt,
            List<String> labels) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            if (hasLabelValue(prompt, label)) {
                present.add("field:" + label);
            }
            else if (absenceExplained(prompt, label)) {
                present.add("explainedAbsence:field:" + label);
            }
            else {
                missing.add("field:" + label);
            }
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness requireAnyLabel(
            FinalPromptSnapshot prompt,
            List<String> labels) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            if (hasLabelValue(prompt, label)) {
                present.add("field:" + label);
            }
            else if (absenceExplained(prompt, label)) {
                present.add("explainedAbsence:field:" + label);
            }
            else {
                missing.add("field:" + label);
            }
        }
        if (!present.isEmpty()) {
            return new FinalPromptMetricInputReadiness(true, List.of(), List.copyOf(present));
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness requireMinLabels(
            FinalPromptSnapshot prompt,
            List<String> labels,
            int minCount) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            if (hasLabelValue(prompt, label)) {
                present.add("field:" + label);
            }
            else if (absenceExplained(prompt, label)) {
                present.add("explainedAbsence:field:" + label);
            }
            else {
                missing.add("field:" + label);
            }
        }
        if (present.size() >= minCount) {
            return new FinalPromptMetricInputReadiness(true, List.of(), List.copyOf(present));
        }
        return result(missing, present);
    }

    private static FinalPromptMetricInputReadiness requireThenInputsWhenTriggered(
            FinalPromptSnapshot prompt,
            FinalPromptMetricRule rule) {
        boolean triggered = rule.terms().stream().anyMatch(term -> promptContains(prompt, term));
        if (!triggered) {
            return allReady();
        }
        if (!rule.thenLabels().isEmpty()) {
            return requireAnyConcreteLabel(prompt, rule.thenLabels());
        }
        return allReady();
    }

    private static FinalPromptMetricInputReadiness requireAnyConcreteLabel(
            FinalPromptSnapshot prompt,
            List<String> labels) {
        List<String> missing = new ArrayList<>();
        List<String> present = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            if (hasLabelValue(prompt, label)) {
                present.add("field:" + label);
            }
            else {
                missing.add("field:" + label);
            }
        }
        if (!present.isEmpty()) {
            return new FinalPromptMetricInputReadiness(true, List.of(), List.copyOf(present));
        }
        return result(missing, present);
    }

    private static boolean hasLabelValue(FinalPromptSnapshot prompt, String label) {
        return prompt != null
                && StringUtils.hasText(label)
                && prompt.fieldsByLabel(label).stream()
                .anyMatch(field -> StringUtils.hasText(field.value()));
    }

    private static boolean promptContains(FinalPromptSnapshot prompt, String term) {
        return prompt != null && prompt.contains(term);
    }

    private static boolean absenceExplained(FinalPromptSnapshot prompt, String concept) {
        if (prompt == null || !StringUtils.hasText(concept)) {
            return false;
        }
        List<String> tokens = conceptTokens(concept);
        if (tokens.isEmpty()) {
            return false;
        }
        return prompt.fields().stream()
                .anyMatch(field -> absenceLineExplains(field.label() + " " + field.value(), tokens))
                || prompt.bullets().stream()
                .anyMatch(bullet -> absenceLineExplains(bullet.text(), tokens))
                || prompt.narrativeLines().stream()
                .anyMatch(line -> absenceLineExplains(line.text(), tokens));
    }

    private static boolean absenceLineExplains(String line, List<String> tokens) {
        if (!StringUtils.hasText(line) || tokens == null || tokens.isEmpty()) {
            return false;
        }
        String normalizedLine = FinalPromptSnapshot.normalizeLabel(line);
        int matches = 0;
        for (String token : tokens) {
            if (token.length() > 1 && normalizedLine.contains(token)) {
                matches++;
            }
        }
        int required = tokens.size() <= 2 ? tokens.size() : Math.min(3, tokens.size());
        if (matches < required) {
            return false;
        }
        String lower = line.toLowerCase(Locale.ROOT);
        return lower.contains("unknown")
                || lower.contains("missing")
                || lower.contains("not available")
                || lower.contains("unavailable")
                || lower.contains("insufficient")
                || lower.contains("limitation")
                || lower.contains("warning")
                || lower.contains("do not assume")
                || lower.contains("avoid assuming")
                || lower.contains("not proof")
                || lower.contains("cannot infer")
                || lower.contains("treat");
    }

    private static List<String> conceptTokens(String concept) {
        if (!StringUtils.hasText(concept)) {
            return List.of();
        }
        String splitCamelCase = concept.replaceAll("([a-z])([A-Z])", "$1 $2");
        String[] raw = splitCamelCase.split("[^\\p{L}\\p{N}]+");
        List<String> tokens = new ArrayList<>();
        for (String token : raw) {
            String normalized = FinalPromptSnapshot.normalizeLabel(token);
            if (StringUtils.hasText(normalized)) {
                tokens.add(normalized);
            }
        }
        return List.copyOf(tokens);
    }

    private static FinalPromptMetricInputReadiness result(List<String> missing, List<String> present) {
        List<String> safeMissing = missing == null ? List.of() : List.copyOf(missing);
        List<String> safePresent = present == null ? List.of() : List.copyOf(present);
        return new FinalPromptMetricInputReadiness(safeMissing.isEmpty(), safeMissing, safePresent);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static int safeMin(Integer value) {
        return value == null ? 1 : value;
    }
}
