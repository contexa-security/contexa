package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.anatomy.SealedPromptViews;
import io.contexa.showcase.portal.reactivity.DeliveryEvaluator;
import io.contexa.showcase.portal.reactivity.ReactivityService;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.4, 5): how the one condition a visitor changed in the lab went
 * into the model's input, step by step: the lines that changed against the designed run of the same case with their
 * values before and after, which of them the condition should change, which it should not have changed, and whether
 * the changed line says the requested value. The comparison is the harness's delivery check
 * (ReactivityService.delivery, DeliveryEvaluator); the values are the sealed prompts' lines, HTTP session identifiers
 * masked.
 *
 * @param baseRunId the designed run compared with ({@link LabStore#designedBase}); null when none was chosen
 * @param condition the changed condition; null unless exactly one was changed
 * @param value     the condition's value in the visitor's run, as the lab stored it
 * @param reason    why there is no comparison: {@link #DESIGNED}, {@link #SEVERAL_CONDITIONS}, {@link #NOT_COMPLETED},
 *                  {@link #NO_BASE} or {@link #NO_ENGINE}; null when compared
 */
public record LabDelta(String runId, String baseRunId, String condition, String value, boolean available,
                       String reason, List<Step> steps) {

    /** Nothing was changed: the run is the designed case. */
    public static final String DESIGNED = "DESIGNED";
    /** More than one condition was changed, so no one condition's expected lines apply. */
    public static final String SEVERAL_CONDITIONS = "SEVERAL_CONDITIONS";
    /** The run has not completed. */
    public static final String NOT_COMPLETED = "NOT_COMPLETED";
    /** No designed run of the same case under the same setting to compare with. */
    public static final String NO_BASE = "NO_BASE";
    /** Control D could not be read. */
    public static final String NO_ENGINE = "NO_ENGINE";

    /** A line that changed, with every value of its label in each run's sealed prompt. */
    public record Change(String label, List<String> before, List<String> after) {
    }

    /**
     * One step compared.
     *
     * @param expected    the changed labels the condition should change
     * @param unexpected  the changed labels the condition should not have changed
     * @param notCompared why the step was not compared (ReactivityService.StepDelivery: NO_VARIANT_STEP, NOT_SEALED,
     *                    NOT_SEALED_ONE_SIDE, NOT_SEALED_AFTER_DIFFERENT_DECISION); null when compared
     * @param unchangedLines the variant's compared lines that did not change, the volatile lines left out as the
     *                       delivery check leaves them out (DeliveryEvaluator); null when not compared
     * @param notLookedUp    N-DLV-4: what the request's work does not look up for the changed condition (a record kind
     *                       or CLAIMED_TICKET, DeliveryEvaluator, N-DLV-2), so its value cannot reach the prompt; null
     *                       when it does or the step was not compared
     */
    public record Step(int stepNo, List<Change> changed, List<String> expected, List<String> unexpected,
                       Boolean valueMatches, boolean passed, String notCompared, Integer unchangedLines,
                       String notLookedUp) {
    }

    /** Why a lab run cannot be compared before a base is looked for; null when it can. */
    static String refusal(LabStore.Composition run) {
        if (run.changed().isEmpty()) {
            return DESIGNED;
        }
        if (run.changed().size() > 1) {
            return SEVERAL_CONDITIONS;
        }
        if (!"COMPLETED".equals(run.status())) {
            return NOT_COMPLETED;
        }
        return null;
    }

    /** The one changed condition; null unless exactly one was changed. */
    static String condition(LabStore.Composition run) {
        return run.changed().size() == 1 ? run.changed().get(0) : null;
    }

    /** The changed condition's value as the lab stored it (4831, true, AFTERNOON); null without one. */
    static String value(LabStore.Composition run) {
        String condition = condition(run);
        Object value = condition == null || run.conditions() == null ? null : run.conditions().get(condition);
        return value == null ? null : String.valueOf(value);
    }

    static LabDelta without(LabStore.Composition run, String baseRunId, String reason) {
        return new LabDelta(run.runId(), baseRunId, condition(run), value(run), false, reason, List.of());
    }

    /**
     * The delta from the harness's comparison of the two runs and the sealed prompts of their requests.
     *
     * @param facts the sealed prompt of each compared request, by request ID (null when control D holds none)
     */
    static LabDelta of(LabStore.Composition run, ReactivityService.RunDelivery delivery, Map<String, JsonNode> facts) {
        List<Step> steps = new ArrayList<>();
        for (ReactivityService.StepDelivery step : delivery.steps()) {
            DeliveryEvaluator.Delivery compared = step.delivery();
            if (compared == null) {
                steps.add(new Step(step.stepNo(), List.of(), List.of(), List.of(), null, false, step.notCompared(),
                        null, null));
                continue;
            }
            Map<String, List<String>> before = values(facts.get(step.baseRequestId()));
            Map<String, List<String>> after = values(facts.get(step.variantRequestId()));
            List<Change> changed = new ArrayList<>();
            for (String label : compared.changed()) {
                changed.add(new Change(label, List.copyOf(before.getOrDefault(label, List.of())),
                        List.copyOf(after.getOrDefault(label, List.of()))));
            }
            steps.add(new Step(step.stepNo(), List.copyOf(changed), compared.delivered(), compared.unexpected(),
                    compared.valueMatches(), compared.passed(), null, compared.unchangedLines(),
                    compared.notLookedUp()));
        }
        return new LabDelta(run.runId(), delivery.baseRunId(), delivery.condition(), delivery.value(), true, null,
                List.copyOf(steps));
    }

    /** Every label's values in a sealed prompt, in prompt order; empty without one. */
    static Map<String, List<String>> values(JsonNode facts) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        if (facts == null) {
            return values;
        }
        for (JsonNode line : facts.path("lines")) {
            String label = line.path("label").asText(null);
            if (label != null) {
                values.computeIfAbsent(label, key -> new ArrayList<>())
                        .add(SealedPromptViews.masked(line.path("value").asText("")));
            }
        }
        return values;
    }
}
