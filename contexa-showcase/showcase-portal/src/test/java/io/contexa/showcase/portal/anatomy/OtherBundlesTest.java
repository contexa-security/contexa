package io.contexa.showcase.portal.anatomy;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.1): the run the prompt modal compares a step with is the latest
 * completed, unforced run of the same definition whose specification names another prompt bundle, with the step's
 * stored text; nothing else stands in for it.
 */
class OtherBundlesTest {

    private static final String SHA = "a".repeat(64);
    private static final String V20 = "2026.10.16-v20.22";
    private static final String V19 = "2026.10.11-v19.8";
    private static final Instant AT = Instant.parse("2026-10-16T03:00:00Z");

    @Test
    void onlyARunOfTheSameDefinitionIsChosen() {
        assertThat(OtherBundles.choose(SHA, V20, List.of(candidate("run-other-def", "b".repeat(64), V19,
                "COMPLETED", false, AT, true)))).isEmpty();
        assertThat(OtherBundles.choose(SHA, V20, List.of(candidate("run-same-def", SHA, V19, "COMPLETED", false, AT,
                true)))).contains("run-same-def");
    }

    @Test
    void onlyARunUnderAnotherNamedBundleIsChosen() {
        assertThat(OtherBundles.choose(SHA, V20, List.of(
                candidate("run-same-bundle", SHA, V20, "COMPLETED", false, AT, true),
                candidate("run-no-bundle", SHA, null, "COMPLETED", false, AT, true)))).isEmpty();
    }

    @Test
    void theLatestStartedRunIsChosen() {
        assertThat(OtherBundles.choose(SHA, V20, List.of(
                candidate("run-older", SHA, V19, "COMPLETED", false, AT.minusSeconds(3600), true),
                candidate("run-latest", SHA, V19, "COMPLETED", false, AT, true),
                candidate("run-old", SHA, V19, "COMPLETED", false, AT.minusSeconds(86400), true))))
                .contains("run-latest");
    }

    @Test
    void forcedFailedAndTextlessRunsAreLeftOut() {
        assertThat(OtherBundles.choose(SHA, V20, List.of(
                candidate("run-forced", SHA, V19, "COMPLETED", true, AT, true),
                candidate("run-failed", SHA, V19, "FAILED", false, AT, true),
                candidate("run-running", SHA, V19, "RUNNING", false, AT, true),
                candidate("run-no-text", SHA, V19, "COMPLETED", false, AT, false),
                candidate("run-kept", SHA, V19, "COMPLETED", false, AT.minusSeconds(60), true))))
                .contains("run-kept");
    }

    @Test
    void withoutTheRunsDefinitionOrBundleNothingIsChosen() {
        List<OtherBundles.Candidate> candidates = List.of(candidate("run-other", SHA, V19, "COMPLETED", false, AT,
                true));

        assertThat(OtherBundles.choose(null, V20, candidates)).isEmpty();
        assertThat(OtherBundles.choose(SHA, null, candidates)).isEmpty();
    }

    private static OtherBundles.Candidate candidate(String runId, String sha, String bundle, String status,
                                                    boolean forced, Instant startedAt, boolean stepText) {
        return new OtherBundles.Candidate(runId, sha, bundle, status, forced, startedAt, stepText);
    }
}
