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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-16: one selector chooses the bundle a request runs; the bundle gives the descriptor, the manifest and the user
 * prompt layout, and the execution record states what chose it. A bundle the build cannot run falls back to the
 * build default. Plan 6-2: the build runs v1.0 alone, so what the selector chose shows in the source it gives; the
 * names of the earlier bundles are names the build cannot run.
 */
class SecurityDecisionPromptBundleSelectionTest {

    private static final String PROMPT_KEY = "cortex.security-decision";
    private static final String V1 = SecurityDecisionPromptBundles.V1.version();
    private static final PromptBudgetProfile L1 = PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
    private static final PromptBudgetProfile L2 = PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT;

    private static SecurityDecisionGoldenRender golden;
    private static JsonNode goldenCase;

    @BeforeAll
    static void load() {
        golden = SecurityDecisionGoldenRender.load();
        goldenCase = golden.cases().get(0);
    }

    @Test
    void theBuildRunsV1AloneAsItsDefault() {
        // Plan 1-9 and 6-2: v1.0 is the build default and the one bundle the build runs; it answers in the short output
        // contract v5 (K30) and has no rollback target, since the product starts at v1.0.
        assertThat(SecurityDecisionPromptBundles.DEFAULT).isSameAs(SecurityDecisionPromptBundles.V1);
        assertThat(V1).isEqualTo("2026.11.16-v1.0");
        assertThat(SecurityDecisionPromptBundles.ALL).containsExactly(SecurityDecisionPromptBundles.V1);
        assertThat(SecurityDecisionPromptBundles.V1.descriptor())
                .isEqualTo(SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);
        assertThat(SecurityDecisionPromptBundles.V1.descriptor().releaseStatus()).isEqualTo(PromptReleaseStatus.PRODUCTION);
        assertThat(SecurityDecisionPromptBundles.V1.descriptor().rollbackPromptVersion()).isNull();
        assertThat(PromptBundleCatalog.shared().find(PROMPT_KEY, V1)).as("manifest of " + V1).isPresent();
        for (String earlier : List.of("2026.10.24-v19.21", "2026.10.24-v20.26", "2026.10.30-v21.19",
                "2026.11.14-v1.0-fallback-similar", "2026.11.15-v1.0", "2026.10.11-v19.5")) {
            assertThat(SecurityDecisionPromptBundles.find(earlier)).as(earlier).isEmpty();
        }
    }

    @Test
    void withoutASelectionTheBuildDefaultBundleRunsInTheV1Layout() {
        // Plan 1-9: nothing chooses a bundle, so the build default v1.0 runs.
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, new TieredStrategyProperties());
        Map<String, Object> metadata = rendered.executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V1)
                .containsEntry("promptBundleVersion", V1)
                .containsEntry("promptBundleSelectionSource", "BUILD_DEFAULT")
                .containsEntry("userPromptLayoutVersion", SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V1);
        assertThat(rendered.userText()).startsWith("=== USER BASELINE");
    }

    @Test
    void theConfiguredBundleRunsWithItsOwnDescriptorManifestAndLayout() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(V1);

        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, properties);
        Map<String, Object> metadata = rendered.executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V1)
                .containsEntry("contractVersion", "CORTEX_PROMPT_CONTRACT_V5")
                .containsEntry("promptBundleVersion", V1)
                .containsEntry("promptBundleHash",
                        PromptBundleCatalog.shared().find(PROMPT_KEY, V1).orElseThrow().bundleHash())
                .containsEntry("promptBundleSelectionSource", "CONFIGURATION")
                .containsEntry("userPromptLayoutVersion", SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V1);
        assertThat(rendered.userText()).startsWith("=== USER BASELINE");
    }

    @Test
    void aBundleTheBuildCannotRunFallsBackToTheBuildDefault() {
        // The earlier bundles (v19, v20, v21, the measured variants) have no render code in this build any more.
        for (String requested : List.of("2026.10.24-v19.21", "2026.10.24-v20.26", "2026.10.30-v21.19",
                "2026.11.14-v1.0-record-exact", "2026.10.11-v19.5", "2099.01.01-v99")) {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(requested);

            SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, properties);

            assertThat(descriptor(rendered.executionMetadata().toMetadataMap()))
                    .as(requested)
                    .containsEntry("promptVersion", V1)
                    .containsEntry("promptBundleSelectionSource", "BUILD_DEFAULT");
            assertThat(rendered.userText()).startsWith("=== USER BASELINE");
        }
    }

    @Test
    void theSourceTheSelectorGivesIsRecordedWithTheBundle() {
        for (PromptBundleSelectionSource source : List.of(PromptBundleSelectionSource.REGISTRY,
                PromptBundleSelectionSource.CANARY)) {
            PromptBundleSelector selector = (context, subject) -> new PromptBundleSelection(V1, source);

            Map<String, Object> descriptor = descriptor(
                    golden.render(goldenCase, L1, selector).executionMetadata().toMetadataMap());

            assertThat(descriptor)
                    .containsEntry("promptVersion", V1)
                    .containsEntry("promptBundleSelectionSource", source.name());
        }
    }

    @Test
    void theSelectorGetsTheRequestContextAndTheUserAsTheSubject() {
        AtomicReference<PromptGovernanceResolutionContext> seenContext = new AtomicReference<>();
        AtomicReference<String> seenSubject = new AtomicReference<>();
        PromptBundleSelector selector = (context, subject) -> {
            seenContext.set(context);
            seenSubject.set(subject);
            return PromptBundleSelection.none();
        };

        golden.render(goldenCase, L1, selector);

        assertThat(seenContext.get().promptKey()).isEqualTo(PROMPT_KEY);
        assertThat(seenContext.get().templateKey())
                .isEqualTo(SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.templateKey());
        assertThat(seenContext.get().registryScope()).isEqualTo("PLATFORM_GLOBAL");
        assertThat(seenSubject.get()).isEqualTo(goldenCase.path("requestFacts").path("userId").asText());
    }

    @Test
    void oneEventKeepsTheBundleItsFirstPromptWasDrawnWith() {
        AtomicReference<PromptBundleSelection> choice =
                new AtomicReference<>(new PromptBundleSelection(V1, PromptBundleSelectionSource.CONFIGURATION));
        AtomicInteger selections = new AtomicInteger();
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null,
                (context, subject) -> {
                    selections.incrementAndGet();
                    return choice.get();
                }, null, null);
        SecurityEvent event = event("event-bundle-1");

        sections.buildStructuredPrompt(event, null, null, List.of(), L1);
        choice.set(new PromptBundleSelection(V1, PromptBundleSelectionSource.REGISTRY));
        Map<String, Object> second = sections.buildStructuredPrompt(event, null, null, List.of(), L2)
                .executionMetadata().toMetadataMap();

        // The Layer2 prompt of the same event (a second pass among them) is drawn with the first prompt's choice.
        assertThat(descriptor(second))
                .containsEntry("promptVersion", V1)
                .containsEntry("promptBundleSelectionSource", "CONFIGURATION");
        assertThat(selections).hasValue(1);

        Map<String, Object> next = sections.buildStructuredPrompt(event("event-bundle-2"), null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();
        assertThat(descriptor(next))
                .containsEntry("promptVersion", V1)
                .containsEntry("promptBundleSelectionSource", "REGISTRY");
        assertThat(selections).hasValue(2);
    }

    /**
     * W3-18: the strategy asks for the event's bundle before its past record search, since the version decides how the
     * past records are read; the prompt drawn later keeps that choice.
     */
    @Test
    void theTemplateFixesTheEventsBundleBeforeThePromptIsDrawn() {
        AtomicReference<PromptBundleSelection> choice =
                new AtomicReference<>(new PromptBundleSelection(V1, PromptBundleSelectionSource.CANARY));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null, null, null,
                (context, subject) -> choice.get());
        SecurityEvent event = event("event-bundle-4");

        assertThat(template.promptBundle(event)).isEqualTo(SecurityDecisionPromptBundles.V1);
        choice.set(new PromptBundleSelection(V1, PromptBundleSelectionSource.REGISTRY));
        Map<String, Object> metadata = template.buildStructuredPrompt(event, null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V1)
                .containsEntry("promptBundleSelectionSource", "CANARY");
        Map<String, Object> next = template.buildStructuredPrompt(event("event-bundle-5"), null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();
        assertThat(descriptor(next)).containsEntry("promptBundleSelectionSource", "REGISTRY");
    }

    @Test
    void theTemplateRunsTheBundleOfTheSelectorItIsGiven() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null, null, null,
                (context, subject) -> new PromptBundleSelection(V1, PromptBundleSelectionSource.REGISTRY));

        Map<String, Object> metadata = template.buildStructuredPrompt(event("event-bundle-3"), null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V1)
                .containsEntry("promptBundleSelectionSource", "REGISTRY");
    }

    private static SecurityEvent event(String eventId) {
        return SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.parse("2026-10-12T03:17:00Z"))
                .userId("alice")
                .sessionId("session-bundle")
                .sourceIp("10.0.0.1")
                .build();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> descriptor(Map<String, Object> metadata) {
        return (Map<String, Object>) metadata.get("governanceDescriptor");
    }
}
