package io.contexa.showcase.portal.orchestrator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Compares two normalised prompts of the same request for the isolation smoke (T6, T7) three ways: exactly, as a set
 * of evidence facts in any order, and by the retrieved documents alone. The engine ranks retrieved documents with a
 * query that contains the principal and tenant names, so two principals with identical memory can receive the same
 * documents in another order (recorded for approval in docs/showcase). Summary lines that show only the first items
 * of a ranked list then show different items, which the fact-set comparison reports as a difference.
 */
public final class PromptComparison {

    private static final Pattern ORDINAL = Pattern.compile(
            "\\b(RagDocument|Doc|ComparableExample|ObservedComparableCombination|signature=)\\d+");
    private static final Pattern SEPARATOR = Pattern.compile(", |\\s\\|\\s|; |\\||: |=");
    private static final Pattern LINE = Pattern.compile("\\R");
    private static final Pattern DOCUMENT = Pattern.compile("^RagDocument\\d+:");

    public record Result(boolean identical, boolean sameEvidenceSet, boolean sameRetrievedDocuments,
                         List<String> differingLabels) {
    }

    private PromptComparison() {
    }

    public static Result compare(String left, String right) {
        boolean identical = left.equals(right);
        return new Result(identical, identical || evidenceSet(left).equals(evidenceSet(right)),
                identical || retrievedDocuments(left).equals(retrievedDocuments(right)),
                identical ? List.of() : differingLabels(left, right));
    }

    /** Labels of the lines that occur in one prompt more often than in the other, in order of appearance. */
    static List<String> differingLabels(String left, String right) {
        Map<String, Integer> counts = new HashMap<>();
        for (String line : LINE.split(left)) {
            counts.merge(line, 1, Integer::sum);
        }
        for (String line : LINE.split(right)) {
            counts.merge(line, -1, Integer::sum);
        }
        Set<String> labels = new LinkedHashSet<>();
        for (String line : LINE.split(left + "\n" + right)) {
            if (counts.getOrDefault(line, 0) != 0) {
                labels.add(label(line));
            }
        }
        return new ArrayList<>(labels);
    }

    /** Every line as its sorted facts with ordinal numbering removed, all lines sorted. */
    static List<String> evidenceSet(String prompt) {
        List<String> lines = new ArrayList<>();
        for (String line : LINE.split(prompt)) {
            lines.add(facts(line));
        }
        lines.sort(String::compareTo);
        return lines;
    }

    /** The retrieved document lines as sorted facts, in any order. */
    static List<String> retrievedDocuments(String prompt) {
        List<String> documents = new ArrayList<>();
        for (String line : LINE.split(prompt)) {
            if (DOCUMENT.matcher(line.trim()).find()) {
                documents.add(facts(line));
            }
        }
        documents.sort(String::compareTo);
        return documents;
    }

    private static String facts(String line) {
        String[] facts = SEPARATOR.split(ORDINAL.matcher(line.trim()).replaceAll("$1#"));
        for (int i = 0; i < facts.length; i++) {
            facts[i] = facts[i].trim();
        }
        Arrays.sort(facts);
        return String.join("\u0001", facts);
    }

    private static String label(String line) {
        String trimmed = line.trim();
        int colon = trimmed.indexOf(':');
        String label = colon > 0 ? trimmed.substring(0, colon) : trimmed;
        return label.length() <= 48 ? label : label.substring(0, 48);
    }
}
