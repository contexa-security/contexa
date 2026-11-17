/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRelease;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-9 (P6-CHANGE-6): a shadow run draws the scope's shadow bundle on a sampled request, apart from the decision: on a
 * copy of the event as it came (its own event and request ids, the candidate bundle chosen, marked as a shadow run)
 * after the decision, within a daily call cap, and sealed as the SHADOW stage. A shadow run never makes another one.
 */
class PromptShadowRunnerTest {

    private static final String CANDIDATE = SecurityDecisionPromptBundles.V1.version();
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-16T01:00:00Z"), ZoneOffset.UTC);

    private final List<Runnable> queued = new ArrayList<>();
    private final List<SecurityEvent> sealed = new ArrayList<>();

    @Test
    void aSampledRequestWithAShadowReleaseGetsAMarkedCopyAndTheOriginalStaysAsItWas() {
        SecurityEvent event = event("evt-1");

        SecurityEvent copy = runner(100, 10, candidate()).prepare(event);

        assertThat(copy).isNotNull();
        assertThat(copy.getEventId()).isEqualTo("evt-1:shadow");
        assertThat(copy.getUserId()).isEqualTo("user-1");
        assertThat(copy.getSessionId()).isEqualTo("session-1");
        assertThat(copy.getMetadata()).containsEntry("promptBundleSelection.version", CANDIDATE)
                .containsEntry("promptBundleSelection.source", "SHADOW")
                .containsEntry(PromptShadowRunner.SHADOW_RUN, true)
                .containsEntry("decisionBoundaryMode", "SHADOW")
                .containsEntry("requestPath", "/api/projects/GB-500/exports");
        assertThat((String) copy.getMetadata().get("requestId")).startsWith("shadow-");
        assertThat(event.getMetadata()).doesNotContainKeys(PromptShadowRunner.SHADOW_RUN,
                "promptBundleSelection.version").containsEntry("requestId", "req-1");
        assertThat(PromptShadowRunner.isShadow(copy)).isTrue();
        assertThat(PromptShadowRunner.isShadow(event)).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void theCopyKeepsNoMapOrListOfTheOriginal() {
        SecurityEvent event = event("evt-7");
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("hours", new ArrayList<>(List.of(9, 10)));
        event.addMetadata("baseline", nested);

        SecurityEvent copy = runner(100, 10, candidate()).prepare(event);
        Map<String, Object> copied = (Map<String, Object>) copy.getMetadata().get("baseline");
        copied.put("added", true);
        ((List<Object>) copied.get("hours")).add(3);

        assertThat(nested).containsOnlyKeys("hours");
        assertThat(nested.get("hours")).isEqualTo(List.of(9, 10));
    }

    @Test
    void theCopyHasNoneOfTheDecisionsIdentitiesSoItsTraceAndSealStayApart() {
        SecurityEvent event = event("evt-9");
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-of-the-decision");
        event.addMetadata("correlationId", "corr-of-the-decision");

        SecurityEvent copy = runner(100, 10, candidate()).prepare(event);

        assertThat(copy.getMetadata()).doesNotContainKeys(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "correlationId");
        assertThat(event.getMetadata()).containsEntry(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-of-the-decision")
                .containsEntry("correlationId", "corr-of-the-decision");
    }

    @Test
    void withoutAShadowReleaseOrOutsideTheSampleThereIsNoCopy() {
        assertThat(runner(100, 10, PromptBundleSelection.none()).prepare(event("evt-2"))).isNull();
        assertThat(runner(0, 10, candidate()).prepare(event("evt-3"))).isNull();
    }

    @Test
    void aShadowReleaseOfABundleOutsideTheBuildIsNotRun() {
        PromptBundleSelection elsewhere = new PromptBundleSelection("2026.01.01-v99.1", PromptBundleSelectionSource.SHADOW);

        assertThat(runner(100, 10, elsewhere).prepare(event("evt-8"))).isNull();
    }

    @Test
    void aShadowRunMakesNoOtherShadowRun() {
        PromptShadowRunner runner = runner(100, 10, candidate());
        SecurityEvent copy = runner.prepare(event("evt-4"));

        assertThat(runner.prepare(copy)).isNull();
    }

    @Test
    void theCopyIsAnalysedApartAndSealedAsTheShadowStageWithinTheDailyCap() {
        PromptShadowRunner runner = runner(100, 1, candidate());
        SecurityEvent first = runner.prepare(event("evt-5"));
        SecurityEvent second = runner.prepare(event("evt-6"));
        List<SecurityEvent> analysed = new ArrayList<>();

        runner.run(first, copy -> {
            analysed.add(copy);
            return ProcessingResult.builder().success(true).build();
        });
        runner.run(second, copy -> {
            analysed.add(copy);
            return ProcessingResult.builder().success(true).build();
        });
        assertThat(analysed).isEmpty();
        queued.forEach(Runnable::run);

        assertThat(analysed).containsExactly(first);
        assertThat(sealed).containsExactly(first);
    }

    /** N-SHD-1: the copy names the request its decision is sealed under and still has a request id of its own. */
    @Test
    void theCopyKeepsTheRequestOfItsDecisionAndStillHasItsOwnRequestId() {
        SecurityEvent event = event("evt-10");

        SecurityEvent copy = runner(100, 10, candidate()).prepare(event);

        assertThat(copy.getMetadata()).containsEntry(PromptShadowRun.ORIGINAL_REQUEST_ID, "req-1");
        assertThat((String) copy.getMetadata().get("requestId")).startsWith("shadow-").isNotEqualTo("req-1");
        assertThat(event.getMetadata()).doesNotContainKey(PromptShadowRun.ORIGINAL_REQUEST_ID)
                .containsEntry("requestId", "req-1");
    }

    /** N-SHD-1: without a request id the copy names the correlation id, else the event id, its decision is sealed under. */
    @Test
    void withoutARequestIdTheCopyNamesTheCorrelationOrTheEventOfItsDecision() {
        SecurityEvent byCorrelation = SecurityEvent.builder().eventId("evt-11").userId("user-1").build();
        byCorrelation.addMetadata("correlationId", "corr-11");
        SecurityEvent byEvent = SecurityEvent.builder().eventId("evt-12").userId("user-1").build();
        PromptShadowRunner runner = runner(100, 10, candidate());

        assertThat(runner.prepare(byCorrelation).getMetadata())
                .containsEntry(PromptShadowRun.ORIGINAL_REQUEST_ID, "corr-11")
                .doesNotContainKey("correlationId");
        assertThat(runner.prepare(byEvent).getMetadata()).containsEntry(PromptShadowRun.ORIGINAL_REQUEST_ID, "evt-12");
    }

    // ----- plan 3.9: the versions of the database -----

    /** The copy of a version of the database is drawn with that version, fixed on it as a decision's version is. */
    @Test
    void aVersionOfTheDatabaseIsFixedOnTheCopyAndTheDecisionsContentHashIsNot() {
        SecurityEvent event = event("evt-20");
        event.addMetadata("promptBundleSelection.contentHash", "hash-of-another-version");

        SecurityEvent copy = runner(100, 10, "v2.0", new PromptShadowRelease("V3.0", null, null)).prepare(event);

        assertThat(copy.getMetadata()).containsEntry("promptBundleSelection.version", "v3.0")
                .containsEntry("promptBundleSelection.source", "SHADOW")
                .doesNotContainKey("promptBundleSelection.contentHash");
    }

    /** A shadow release that is the version the request's decision runs is not run a second time. */
    @Test
    void theVersionTheDecisionRunsIsNotRunAgainAlongsideIt() {
        assertThat(runner(100, 10, "v2.0", new PromptShadowRelease("v2.0", null, null)).prepare(event("evt-21")))
                .isNull();

        SecurityEvent fixed = event("evt-22");
        fixed.addMetadata("promptBundleSelection.version", "v3.0");
        assertThat(runner(100, 10, "v2.0", new PromptShadowRelease("v3.0", null, null)).prepare(fixed)).isNull();
        assertThat(runner(100, 10, "v2.0", new PromptShadowRelease("v3.0", null, null)).prepare(event("evt-23")))
                .isNotNull();
    }

    /** The registry row's sample share runs in place of the configured one; an empty one keeps the configured share. */
    @Test
    void theRowsSampleShareRunsInPlaceOfTheConfiguredOne() {
        assertThat(runner(0, 10, "v1.0", new PromptShadowRelease("v2.0", 100, null)).prepare(event("evt-24")))
                .isNotNull();
        assertThat(runner(100, 10, "v1.0", new PromptShadowRelease("v2.0", 0, null)).prepare(event("evt-25")))
                .isNull();
        assertThat(runner(0, 10, "v1.0", new PromptShadowRelease("v2.0", null, null)).prepare(event("evt-26")))
                .isNull();
        // A share takes the requests whose event id falls inside it, the same request always on the same side.
        PromptShadowRunner half = runner(0, 10, "v1.0", new PromptShadowRelease("v2.0", 50, null));
        long sampled = IntStream.range(0, 400).mapToObj(index -> event("evt-share-" + index))
                .filter(sample -> half.prepare(sample) != null).count();
        assertThat(sampled).isBetween(150L, 250L);
        assertThat(half.prepare(event("evt-share-7")) != null).isEqualTo(half.prepare(event("evt-share-7")) != null);
    }

    /** The registry row's daily limit runs in place of the configured cap; each release counts its own calls. */
    @Test
    void theRowsDailyLimitRunsInPlaceOfTheConfiguredCap() {
        PromptShadowRunner runner = runner(100, 10, "v1.0", new PromptShadowRelease("v2.0", null, 1));
        SecurityEvent first = runner.prepare(event("evt-27"));
        SecurityEvent second = runner.prepare(event("evt-28"));
        List<SecurityEvent> analysed = new ArrayList<>();

        runner.run(first, copy -> {
            analysed.add(copy);
            return ProcessingResult.builder().success(true).build();
        });
        runner.run(second, copy -> {
            analysed.add(copy);
            return ProcessingResult.builder().success(true).build();
        });
        queued.forEach(Runnable::run);

        assertThat(analysed).containsExactly(first);
    }

    /** A row's limit above the configured cap runs as many shadow runs a day as it sets. */
    @Test
    void aRowsLimitAboveTheConfiguredCapRunsAsManyAsItSets() {
        PromptShadowRunner runner = runner(100, 1, "v1.0", new PromptShadowRelease("v2.0", null, 3));
        int taken = 0;
        for (int index = 0; index < 5; index++) {
            int before = queued.size();
            runner.run(runner.prepare(event("evt-day-" + index)), copy -> ProcessingResult.builder().success(true)
                    .build());
            taken += queued.size() - before;
        }

        assertThat(taken).isEqualTo(3);
    }

    private PromptShadowRunner runner(int samplePercent, int dailyCallCap, String deciding, PromptShadowRelease shadow) {
        PromptBundleSelector selector = new PromptBundleSelector() {
            @Override
            public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
                return new PromptBundleSelection(deciding, PromptBundleSelectionSource.REGISTRY);
            }

            @Override
            public PromptShadowRelease shadowRelease(PromptGovernanceResolutionContext context, String subjectKey) {
                return shadow;
            }
        };
        return runner(samplePercent, dailyCallCap, selector);
    }

    private PromptShadowRunner runner(int samplePercent, int dailyCallCap, PromptBundleSelection selection) {
        PromptBundleSelector selector = new PromptBundleSelector() {
            @Override
            public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
                return PromptBundleSelection.none();
            }

            @Override
            public PromptBundleSelection shadow(PromptGovernanceResolutionContext context, String subjectKey) {
                return selection;
            }
        };
        return runner(samplePercent, dailyCallCap, selector);
    }

    private PromptShadowRunner runner(int samplePercent, int dailyCallCap, PromptBundleSelector selector) {
        return new PromptShadowRunner(selector, event -> new PromptGovernanceResolutionContext("PLATFORM_GLOBAL",
                "cortex.security-decision", "SecurityDecisionStandard", null, null, null, null, Map.of()),
                queued::add, (copy, result) -> {
                    assertThat(result.getAnalysisData()).containsEntry("decisionAppliedStage", "SHADOW");
                    sealed.add(copy);
                }, samplePercent, dailyCallCap, CLOCK);
    }

    private static PromptBundleSelection candidate() {
        return new PromptBundleSelection(CANDIDATE, PromptBundleSelectionSource.SHADOW);
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder().eventId(eventId).userId("user-1").sessionId("session-1").build();
        event.addMetadata("requestId", "req-1");
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        return event;
    }
}
