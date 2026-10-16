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
 * build default.
 */
class SecurityDecisionPromptBundleSelectionTest {

    private static final String PROMPT_KEY = "cortex.security-decision";
    private static final String V19 = "2026.10.16-v19.19";
    private static final String V20 = "2026.10.16-v20.23";
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
    void theBuildRunsTheCurrentBundleAndOnePreviousOneWithTheV19BundleAsItsDefault() {
        assertThat(SecurityDecisionPromptBundles.ALL)
                .extracting(bundle -> bundle.descriptor().promptVersion())
                .containsExactly(V19, V20);
        assertThat(SecurityDecisionPromptBundles.DEFAULT.descriptor())
                .isEqualTo(SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);
        assertThat(SecurityDecisionPromptBundles.DEFAULT.layout())
                .isEqualTo(SecurityDecisionPromptBundles.UserPromptLayout.V19_SECTIONS);
        assertThat(SecurityDecisionPromptBundles.find(V20).orElseThrow().layout())
                .isEqualTo(SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS);
        assertThat(SecurityDecisionPromptBundles.find("2026.10.11-v19.5")).isEmpty();
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            assertThat(PromptBundleCatalog.shared().find(PROMPT_KEY, bundle.descriptor().promptVersion()))
                    .as("manifest of " + bundle.descriptor().promptVersion())
                    .isPresent();
        }
    }

    @Test
    void withoutASelectionTheBuildDefaultBundleRunsInTheV19Layout() {
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, new TieredStrategyProperties());
        Map<String, Object> metadata = rendered.executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V19)
                .containsEntry("promptBundleVersion", V19)
                .containsEntry("promptBundleSelectionSource", "BUILD_DEFAULT");
        assertThat(metadata).doesNotContainKey("userPromptLayoutVersion");
        assertThat(rendered.userText()).doesNotStartWith("=== USER BASELINE");
    }

    @Test
    void theConfiguredBundleRunsWithItsOwnDescriptorManifestAndLayout() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(V20);

        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, properties);
        Map<String, Object> metadata = rendered.executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V20)
                .containsEntry("contractVersion", "CORTEX_PROMPT_CONTRACT_V3")
                .containsEntry("promptBundleVersion", V20)
                .containsEntry("promptBundleHash",
                        PromptBundleCatalog.shared().find(PROMPT_KEY, V20).orElseThrow().bundleHash())
                .containsEntry("promptBundleSelectionSource", "CONFIGURATION")
                .containsEntry("userPromptLayoutVersion", SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V20);
        assertThat(rendered.userText()).startsWith("=== USER BASELINE");
    }

    @Test
    void aBundleTheBuildCannotRunFallsBackToTheBuildDefault() {
        // 2026.10.11-v19.5 has a manifest as a record, but no render code in this build.
        for (String requested : List.of("2026.10.11-v19.5", "2099.01.01-v99")) {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(requested);

            SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase, L1, properties);

            assertThat(descriptor(rendered.executionMetadata().toMetadataMap()))
                    .as(requested)
                    .containsEntry("promptVersion", V19)
                    .containsEntry("promptBundleSelectionSource", "BUILD_DEFAULT");
            assertThat(rendered.userText()).doesNotStartWith("=== USER BASELINE");
        }
    }

    @Test
    void theSourceTheSelectorGivesIsRecordedWithTheBundle() {
        for (PromptBundleSelectionSource source : List.of(PromptBundleSelectionSource.REGISTRY,
                PromptBundleSelectionSource.CANARY)) {
            PromptBundleSelector selector = (context, subject) -> new PromptBundleSelection(V20, source);

            Map<String, Object> descriptor = descriptor(
                    golden.render(goldenCase, L1, selector).executionMetadata().toMetadataMap());

            assertThat(descriptor)
                    .containsEntry("promptVersion", V20)
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
                new AtomicReference<>(new PromptBundleSelection(V20, PromptBundleSelectionSource.CONFIGURATION));
        AtomicInteger selections = new AtomicInteger();
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null,
                (context, subject) -> {
                    selections.incrementAndGet();
                    return choice.get();
                }, null, null);
        SecurityEvent event = event("event-bundle-1");

        sections.buildStructuredPrompt(event, null, null, List.of(), L1);
        choice.set(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));
        Map<String, Object> second = sections.buildStructuredPrompt(event, null, null, List.of(), L2)
                .executionMetadata().toMetadataMap();

        // The Layer2 prompt of the same event (a second pass among them) is drawn with the first prompt's bundle.
        assertThat(descriptor(second))
                .containsEntry("promptVersion", V20)
                .containsEntry("promptBundleSelectionSource", "CONFIGURATION");
        assertThat(selections).hasValue(1);

        Map<String, Object> next = sections.buildStructuredPrompt(event("event-bundle-2"), null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();
        assertThat(descriptor(next))
                .containsEntry("promptVersion", V19)
                .containsEntry("promptBundleSelectionSource", "REGISTRY");
        assertThat(selections).hasValue(2);
    }

    /**
     * W3-18: the strategy asks for the event's bundle before its past record search, since a v20 bundle reads its past
     * records by the exact lookup; the prompt drawn later keeps that bundle.
     */
    @Test
    void theTemplateFixesTheEventsBundleBeforeThePromptIsDrawn() {
        AtomicReference<PromptBundleSelection> choice =
                new AtomicReference<>(new PromptBundleSelection(V20, PromptBundleSelectionSource.CANARY));
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null, null, null,
                (context, subject) -> choice.get());
        SecurityEvent event = event("event-bundle-4");

        assertThat(template.promptBundle(event)).isEqualTo(SecurityDecisionPromptBundles.V20);
        choice.set(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));
        Map<String, Object> metadata = template.buildStructuredPrompt(event, null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V20)
                .containsEntry("promptBundleSelectionSource", "CANARY");
        assertThat(template.promptBundle(event("event-bundle-5"))).isEqualTo(SecurityDecisionPromptBundles.DEFAULT);
    }

    @Test
    void theTemplateRunsTheBundleOfTheSelectorItIsGiven() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(), new TieredStrategyProperties(), null, null, null, null,
                (context, subject) -> new PromptBundleSelection(V20, PromptBundleSelectionSource.REGISTRY));

        Map<String, Object> metadata = template.buildStructuredPrompt(event("event-bundle-3"), null, null, List.of(), L1)
                .executionMetadata().toMetadataMap();

        assertThat(descriptor(metadata))
                .containsEntry("promptVersion", V20)
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
