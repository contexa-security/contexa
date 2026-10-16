package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.1): a step's prompt next to the same step of the same case under
 * the other prompt bundle ({@link OtherBundles}), each with the bundle its seal names as the source of the text.
 *
 * @param reason why there is no comparison: {@link OtherBundles#NO_OTHER_BUNDLE_RUN}, {@link SealedPrompts#NOT_SEALED},
 *               {@link SealedPrompts#NO_ENGINE}, {@link SealedPrompts#NO_STEP}, or the anatomy's
 *               {@link AnatomyStore#PAST_RETENTION} and {@link AnatomyStore#NOT_COLLECTED} when the step's own text is
 *               no longer or never stored; null when both sides are given
 * @param current the step asked for; null when it has no decision, seal or text
 * @param other   the same step under the other bundle; null without one
 */
public record OtherBundleView(boolean available, String reason, Side current, Side other) {

    /** The bundle a seal names: version, hash and where it was selected from. */
    public record Bundle(String version, String hash, String selectionSource) {
    }

    /**
     * One side of the comparison.
     *
     * @param userPrompt        the user prompt the model got at the step
     * @param systemPromptLines how many lines the system prompt of that call has; null when it is not stored
     */
    public record Side(String runId, int stepNo, Bundle bundle, String userPrompt, Integer systemPromptLines) {
    }

    static OtherBundleView of(Side current, Side other) {
        return new OtherBundleView(true, null, current, other);
    }

    static OtherBundleView without(String reason, Side current) {
        return new OtherBundleView(false, reason, current, null);
    }

    /** A side from the step's seal (as control D gives it) and its stored texts. */
    static Side side(String runId, int stepNo, JsonNode facts, OtherBundles.StepText stored) {
        Bundle bundle = new Bundle(field(facts, "promptBundleVersion"), field(facts, "promptBundleHash"),
                field(facts, "promptBundleSelectionSource"));
        return new Side(runId, stepNo, bundle, SealedPromptViews.masked(stored.userPrompt()),
                stored.systemPrompt() == null ? null : (int) stored.systemPrompt().lines().count());
    }

    private static String field(JsonNode facts, String name) {
        JsonNode node = facts.path(name);
        return node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
