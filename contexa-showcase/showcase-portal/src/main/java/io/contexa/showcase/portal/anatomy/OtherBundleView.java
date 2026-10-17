package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * @param lines   N-UI-1: both user prompts' lengths, the earlier bundle first; null without the other side or when
 *                the two versions cannot be ordered
 */
public record OtherBundleView(boolean available, String reason, Side current, Side other, Lines lines) {

    /** The bundle a seal names: version, hash and where it was selected from. */
    public record Bundle(String version, String hash, String selectionSource) {
    }

    /**
     * One side of the comparison.
     *
     * @param userPrompt        the user prompt the model got at the step
     * @param systemPromptLines how many lines the system prompt of that call has; null when it is not stored
     * @param userPromptLines   N-UI-1: how many content lines that user prompt has (PromptLines' rule, D-38); null
     *                          without the text
     */
    public record Side(String runId, int stepNo, Bundle bundle, String userPrompt, Integer systemPromptLines,
                       Integer userPromptLines) {
    }

    /**
     * N-UI-1 (design 3.1, U2-6): the same case's user prompt length under the earlier and the later bundle.
     *
     * @param before      the earlier bundle: its generation ({@code v19}) when the two differ in it, else with its
     *                    number ({@code v20.22})
     * @param beforeLines the content lines of the earlier bundle's user prompt
     * @param after       the later bundle, named the same way
     * @param afterLines  the content lines of the later bundle's user prompt
     */
    public record Lines(String before, int beforeLines, String after, int afterLines) {
    }

    static OtherBundleView of(Side current, Side other) {
        return new OtherBundleView(true, null, current, other, lines(current, other));
    }

    static OtherBundleView without(String reason, Side current) {
        return new OtherBundleView(false, reason, current, null, null);
    }

    /**
     * N-UI-1 (U2-6): the two sides' user prompt lengths, the earlier bundle first by its generation, then its number
     * ({@code 2026.10.16-v20.23}: 20, then 23); null when a length or a version cannot be read, or both versions read
     * the same.
     */
    static Lines lines(Side one, Side two) {
        Version first = Version.of(one.bundle().version());
        Version second = Version.of(two.bundle().version());
        if (first == null || second == null || one.userPromptLines() == null || two.userPromptLines() == null) {
            return null;
        }
        int order = first.generation() != second.generation()
                ? Integer.compare(first.generation(), second.generation())
                : Integer.compare(first.number(), second.number());
        if (order == 0) {
            return null;
        }
        boolean numbered = first.generation() == second.generation();
        Side before = order < 0 ? one : two;
        Side after = order < 0 ? two : one;
        return new Lines((order < 0 ? first : second).name(numbered), before.userPromptLines(),
                (order < 0 ? second : first).name(numbered), after.userPromptLines());
    }

    /** A bundle version's generation and number ({@code v20.23}); the number -1 when the version has none. */
    private record Version(int generation, int number) {

        private static final Pattern FORM = Pattern.compile("v(\\d{1,4})(?:\\.(\\d{1,4}))?$");

        static Version of(String version) {
            Matcher matcher = version == null ? null : FORM.matcher(version);
            if (matcher == null || !matcher.find()) {
                return null;
            }
            return new Version(Integer.parseInt(matcher.group(1)),
                    matcher.group(2) == null ? -1 : Integer.parseInt(matcher.group(2)));
        }

        String name(boolean numbered) {
            return "v" + generation + (numbered && number >= 0 ? "." + number : "");
        }
    }

    /** A side from the step's seal (as control D gives it) and its stored texts. */
    static Side side(String runId, int stepNo, JsonNode facts, OtherBundles.StepText stored) {
        Bundle bundle = new Bundle(field(facts, "promptBundleVersion"), field(facts, "promptBundleHash"),
                field(facts, "promptBundleSelectionSource"));
        String userPrompt = SealedPromptViews.masked(stored.userPrompt());
        return new Side(runId, stepNo, bundle, userPrompt,
                stored.systemPrompt() == null ? null : (int) stored.systemPrompt().lines().count(),
                userPrompt == null ? null : PromptLines.of(null, userPrompt).user());
    }

    private static String field(JsonNode facts, String name) {
        JsonNode node = facts.path(name);
        return node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
