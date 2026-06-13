package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;

public record FinalPromptMetricRule(
        String operator,
        List<String> sections,
        List<String> labels,
        List<List<String>> labelGroups,
        List<String> terms,
        List<String> forbiddenTerms,
        String field,
        String equals,
        Integer minCount,
        List<String> thenTerms,
        List<String> thenLabels,
        List<FinalPromptMetricRule> all,
        List<FinalPromptMetricRule> any
) {
    public FinalPromptMetricRule {
        sections = copyElements(sections, "sections");
        labels = copyElements(labels, "labels");
        labelGroups = copyLabelGroups(labelGroups);
        terms = copyElements(terms, "terms");
        forbiddenTerms = copyElements(forbiddenTerms, "forbiddenTerms");
        thenTerms = copyElements(thenTerms, "thenTerms");
        thenLabels = copyElements(thenLabels, "thenLabels");
        all = copyElements(all, "all");
        any = copyElements(any, "any");
    }

    private static <T> List<T> copyElements(List<T> values, String fieldName) {
        if (values == null) {
            return List.of();
        }
        for (int index = 0; index < values.size(); index++) {
            if (values.get(index) == null) {
                throw new IllegalArgumentException("Final prompt metric rule " + fieldName
                        + " contains null at index " + index + ".");
            }
        }
        return List.copyOf(values);
    }

    private static List<List<String>> copyLabelGroups(List<List<String>> groups) {
        if (groups == null) {
            return List.of();
        }
        for (int groupIndex = 0; groupIndex < groups.size(); groupIndex++) {
            List<String> group = groups.get(groupIndex);
            if (group == null) {
                throw new IllegalArgumentException("Final prompt metric rule labelGroups contains null group at index "
                        + groupIndex + ".");
            }
            for (int valueIndex = 0; valueIndex < group.size(); valueIndex++) {
                if (group.get(valueIndex) == null) {
                    throw new IllegalArgumentException("Final prompt metric rule labelGroups[" + groupIndex
                            + "] contains null at index " + valueIndex + ".");
                }
            }
        }
        return groups.stream().map(List::copyOf).toList();
    }
}
