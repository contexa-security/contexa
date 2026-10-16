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

        assertThat(names(view)).containsExactlyInAnyOrder("available", "reason", "current", "other");
        assertThat(names(view.path("current"))).containsExactlyInAnyOrder("runId", "stepNo", "bundle", "userPrompt",
                "systemPromptLines");
        assertThat(names(view.path("other").path("bundle"))).containsExactlyInAnyOrder("version", "hash",
                "selectionSource");
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
