package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.1): each side of the prompt modal names the bundle its seal names
 * (version, hash, where it was selected) and gives the stored user prompt, HTTP session identifiers masked, with the
 * line count of its system prompt.
 */
class OtherBundleViewTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SESSION_ID = "0123456789ABCDEF0123456789ABCDEF";

    @Test
    void aSideNamesItsSealsBundleAndGivesTheStoredText() throws Exception {
        OtherBundleView.Side side = OtherBundleView.side("run-0123456789ab", 1, sealed("2026.10.16-v20.22", "c6b5",
                "CONFIGURATION"), new OtherBundles.StepText("=== SESSION ===\nSessionId: " + SESSION_ID + "\n",
                "line one\nline two\nline three\n"));

        assertThat(side.bundle()).isEqualTo(new OtherBundleView.Bundle("2026.10.16-v20.22", "c6b5", "CONFIGURATION"));
        assertThat(side.userPrompt()).isEqualTo("=== SESSION ===\nSessionId: <SESSION>\n");
        assertThat(side.systemPromptLines()).isEqualTo(3);
        assertThat(side.runId()).isEqualTo("run-0123456789ab");
        assertThat(side.stepNo()).isEqualTo(1);
    }

    @Test
    void aSideWithoutAStoredSystemPromptCountsNoLines() throws Exception {
        OtherBundleView.Side side = OtherBundleView.side("run-0123456789ab", 2, sealed("v19", "ab12", "BUILD_DEFAULT"),
                new OtherBundles.StepText("user", null));

        assertThat(side.systemPromptLines()).isNull();
        assertThat(side.bundle().selectionSource()).isEqualTo("BUILD_DEFAULT");
    }

    @Test
    void withoutTheOtherSideTheViewSaysWhyAndKeepsTheStep() throws Exception {
        OtherBundleView.Side current = OtherBundleView.side("run-0123456789ab", 1, sealed("v20", "c6b5",
                "CONFIGURATION"), new OtherBundles.StepText("user", "system"));

        OtherBundleView view = OtherBundleView.without(OtherBundles.NO_OTHER_BUNDLE_RUN, current);

        assertThat(view.available()).isFalse();
        assertThat(view.reason()).isEqualTo("NO_OTHER_BUNDLE_RUN");
        assertThat(view.current()).isEqualTo(current);
        assertThat(view.other()).isNull();
        assertThat(OtherBundleView.of(current, current).available()).isTrue();
    }

    @Test
    void theViewHasTheContractsFields() throws Exception {
        OtherBundleView.Side side = OtherBundleView.side("run-0123456789ab", 1, sealed("v20", "c6b5", "CONFIGURATION"),
                new OtherBundles.StepText("user", "system"));

        JsonNode view = JSON.valueToTree(OtherBundleView.of(side, side));

        assertThat(names(view)).containsExactlyInAnyOrder("available", "reason", "current", "other", "lines");
        assertThat(names(view.path("current"))).containsExactlyInAnyOrder("runId", "stepNo", "bundle", "userPrompt",
                "systemPromptLines", "userPromptLines");
        assertThat(names(view.path("other").path("bundle"))).containsExactlyInAnyOrder("version", "hash",
                "selectionSource");
    }

    @Test
    void theViewStatesBothUserPromptLengthsTheEarlierBundleFirst() throws Exception {
        OtherBundleView.Side now = side("2026.10.16-v20.23", "=== REQUEST ===\nTime: Wed 03:17\n\nSize: 4,831 items\n");
        OtherBundleView.Side measured = side("2026.10.11-v19.19", "=== CURRENT REQUEST AND EVENT ===\na\nb\n\nc\nd\n");

        assertThat(now.userPromptLines()).as("N-UI-1: content lines, the blank one left out").isEqualTo(3);
        assertThat(measured.userPromptLines()).isEqualTo(5);
        assertThat(OtherBundleView.of(now, measured).lines()).isEqualTo(new OtherBundleView.Lines("v19", 5, "v20", 3));
        assertThat(OtherBundleView.of(measured, now).lines()).as("whichever side is the step asked for")
                .isEqualTo(new OtherBundleView.Lines("v19", 5, "v20", 3));
    }

    @Test
    void oneGenerationsBundlesAreNamedWithTheirNumbersInNumberOrder() throws Exception {
        OtherBundleView.Side ninth = side("2026.10.15-v20.9", "a\nb\n");
        OtherBundleView.Side later = side("2026.10.16-v20.23", "a\nb\nc\n");

        assertThat(OtherBundleView.of(later, ninth).lines()).as("N-UI-1: 9 before 23, not in text order")
                .isEqualTo(new OtherBundleView.Lines("v20.9", 2, "v20.23", 3));
        assertThat(OtherBundleView.of(later, side("custom", "a\n")).lines()).as("a version without a number").isNull();
        assertThat(OtherBundleView.of(later, later).lines()).as("the same version cannot be ordered").isNull();
        assertThat(OtherBundleView.without(OtherBundles.NO_OTHER_BUNDLE_RUN, later).lines()).isNull();
    }

    /** N-UI-1: a side of the given bundle version and stored user prompt. */
    private static OtherBundleView.Side side(String version, String userPrompt) throws Exception {
        return OtherBundleView.side("run-0123456789ab", 1, sealed(version, "c6b5", "REGISTRY"),
                new OtherBundles.StepText(userPrompt, null));
    }

    private static JsonNode sealed(String version, String hash, String source) throws Exception {
        return JSON.readTree("{\"packageId\": \"pkg-1\", \"promptBundleVersion\": \"" + version
                + "\", \"promptBundleHash\": \"" + hash + "\", \"promptBundleSelectionSource\": \"" + source
                + "\", \"lines\": []}");
    }

    private static List<String> names(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
