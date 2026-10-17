package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * N-DEP-1: the comparison of a v20 decision with the usual behaviour, as the engine sealed it. A v20 user prompt
 * renders no label matrix, so the v19 labels the anatomy reads ({@link AnatomyBuilder#DIMENSIONS}) are not there; the
 * engine's decision facts are, in the sealed canonical context of the decision record (decisionFacts.deviations), the
 * one computation the prompt's DeviationsFromBaseline and SameAsBaseline lines are drawn from. Every value is copied;
 * nothing is compared here.
 */
public final class SealedDeviations {

    /** The user prompt layout of a v20 decision, as its record names it (metadata userPromptLayoutVersion). */
    public static final String V20_LAYOUT = "v20-dictionary-blocks";
    /** The prompt line that states the differences and the dimensions not compared. */
    static final String DIFFERENT_LINE = "DeviationsFromBaseline";
    /** The prompt line that states the dimensions whose value the usual behaviour holds. */
    static final String SAME_LINE = "SameAsBaseline";
    /** The comparison's value of a dimension the engine states as different, as the v19 labels write it. */
    private static final String NOT_IN_USUAL = "false";

    /**
     * The core's deviation dimensions (DeviationDimension, in its order) under the anatomy's dimension names: the v19
     * name where the core compares the same request value (the hour, the day, the network, the login method, the
     * action family, the resource class), a name of its own where v19 had no such comparison.
     */
    static final Map<String, String> DIMENSIONS = dimensions();

    private SealedDeviations() {
    }

    /**
     * The sealed comparison of a decision, one entry per deviation in the engine's order: the deviation's current value
     * and whether the value was seen before, or for a dimension not compared the engine's UNKNOWN with why. Null when
     * the record is not of the v20 layout or holds no sealed deviations (a v19 record keeps its labels).
     */
    public static List<DecisionAnatomy.Comparison> comparisons(JsonNode metadata) {
        if (metadata == null || !V20_LAYOUT.equals(metadata.path("userPromptLayoutVersion").asText(null))) {
            return null;
        }
        JsonNode deviations = metadata.path("sealedEvidence.canonicalContext").path("decisionFacts")
                .path("deviations");
        if (!deviations.isArray()) {
            return null;
        }
        List<DecisionAnatomy.Comparison> comparisons = new ArrayList<>();
        for (JsonNode deviation : deviations) {
            String dimension = text(deviation.path("dimension"));
            boolean compared = deviation.path("compared").asBoolean(false);
            boolean different = deviation.path("different").asBoolean(false);
            comparisons.add(new DecisionAnatomy.Comparison(DIMENSIONS.getOrDefault(dimension, dimension),
                    text(deviation.path("current")), compared ? String.valueOf(!different) : notCompared(deviation),
                    List.of(compared && !different ? SAME_LINE : DIFFERENT_LINE)));
        }
        return List.copyOf(comparisons);
    }

    /** Whether a comparison is a v20 record's: its entries name the prompt line they are read from. */
    public static boolean sealed(List<DecisionAnatomy.Comparison> comparisons) {
        return comparisons != null && comparisons.stream().anyMatch(comparison -> comparison.labels() != null
                && (comparison.labels().contains(DIFFERENT_LINE) || comparison.labels().contains(SAME_LINE)));
    }

    /**
     * How many dimensions the engine sealed as different from the usual behaviour, explained or not: the n of the
     * prompt's "DeviationsFromBaseline: n of m compared". Null as {@link #comparisons}.
     */
    public static Integer differentCount(JsonNode metadata) {
        List<DecisionAnatomy.Comparison> comparisons = comparisons(metadata);
        return comparisons == null ? null
                : (int) comparisons.stream().filter(comparison -> NOT_IN_USUAL.equals(comparison.inUsual())).count();
    }

    /**
     * The metadata of a decision's first record (control D's answer or a stored row: records[0].metadataJson, as text
     * or as an object); null when there is none or it cannot be read, and the caller reads the decision without it.
     */
    public static JsonNode metadata(JsonNode decision, ObjectMapper json) {
        JsonNode records = decision == null ? null : decision.path("records");
        JsonNode metadata = records != null && records.isArray() && !records.isEmpty()
                ? records.get(0).path("metadataJson") : null;
        if (metadata == null || metadata.isObject()) {
            return metadata;
        }
        if (!metadata.isTextual() || metadata.asText().isBlank()) {
            return null;
        }
        try {
            return json.readTree(metadata.asText());
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /** A dimension the engine could not compare: its explanation (UNKNOWN) and why, as the engine sealed them. */
    private static String notCompared(JsonNode deviation) {
        String explanation = text(deviation.path("explanation"));
        String reason = text(deviation.path("notComparedReason"));
        if (explanation == null || reason == null) {
            return explanation != null ? explanation : reason;
        }
        return explanation + " - " + reason;
    }

    private static String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Map<String, String> dimensions() {
        Map<String, String> dimensions = new LinkedHashMap<>();
        dimensions.put("TIME", "accessHour");
        dimensions.put("DAY", "dayOfWeek");
        dimensions.put("NETWORK", "network");
        dimensions.put("DEVICE", "device");
        dimensions.put("LOGIN_METHOD", "authenticationType");
        dimensions.put("TARGET", "target");
        dimensions.put("ACTION", "actionFamily");
        dimensions.put("RESOURCE_CLASS", "resourceFamily");
        dimensions.put("SIZE", "size");
        dimensions.put("RATE", "rate");
        return Collections.unmodifiableMap(dimensions);
    }
}
