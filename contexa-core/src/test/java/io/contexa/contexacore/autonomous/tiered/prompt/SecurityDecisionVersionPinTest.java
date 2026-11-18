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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.4 and 6-3: the version a decision runs is fixed on its event when the decision starts (its name, what chose it,
 * its content hash), and every later prompt of the decision runs it, the Layer2 prompt, the second pass, the correction
 * and a judgement again, while the label moves; the next decision runs where the label points. A name the store cannot
 * find runs the product version and is reported once (plan 3.8, 7).
 */
@ExtendWith(OutputCaptureExtension.class)
class SecurityDecisionVersionPinTest {

    private static final PromptBudgetProfile L1 = PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
    private static final PromptBudgetProfile L2 = PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT;
    private static final String LATER_SENTENCE = "5. When the facts cannot separate the explanations, say what is"
            + " missing (later release).";
    private static final String LATER_CORRECTION = "The earlier answer did not follow the output contract";

    /** The product of a later Contexa release: another sentence of how to judge and another correction. */
    private static final AssembledPrompt LATER_PRODUCT = new PromptAssembler().product(new PromptVersionDocumentReader()
            .read(SecurityDecisionPromptDocument.resource("2026.11.16")
                    .replace("release: 2026.11.16-v1.0", "release: 2026.12.01-v1.1")
                    .replace("5. When the facts cannot separate the explanations, say what is missing.", LATER_SENTENCE)
                    .replace("The previous answer did not follow the output contract", LATER_CORRECTION)));
    /** An organization's version on the current product. */
    private static final AssembledPrompt ORGANIZATION = new PromptAssembler().apply(
            SecurityDecisionPromptDocument.product(), new PromptVersionDocumentReader().read("""
                    prompt: cortex.security-decision
                    basedOn: v1.0
                    title: Finance closing
                    system:
                      - key: how-to-judge
                        text: |
                          1. Weigh the duty roster first.
                    """));
    private static final Map<String, AssembledPrompt> VERSIONS = Map.of(
            "v1.0", SecurityDecisionPromptDocument.product(), "v2.0", ORGANIZATION, "v3.0", LATER_PRODUCT);
    private static final PromptVersionStore STORE = (prompt, name) -> Optional.ofNullable(VERSIONS.get(name));

    private final AtomicReference<PromptBundleSelection> label =
            new AtomicReference<>(new PromptBundleSelection("v3.0", PromptBundleSelectionSource.REGISTRY));

    private SecurityDecisionPromptSections sections() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                new TieredStrategyProperties(), null, null, (context, subject) -> label.get(), null, null);
        sections.setPromptVersionStore(STORE);
        return sections;
    }

    @Test
    void aDecisionThatStartedKeepsItsVersionInEveryPromptWhileTheLabelMoves() {
        SecurityDecisionPromptSections sections = sections();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(sections);
        SecurityEvent event = event("event-pin-1");

        // The strategy fixes the version at the start of the analysis, before its past record search.
        template.promptBundle(event);
        assertThat(event.getMetadata())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION, "v3.0")
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE, "REGISTRY")
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH, LATER_PRODUCT.contentHash());
        SecurityDecisionStandardPromptTemplate.StructuredPrompt first =
                sections.buildStructuredPrompt(event, null, null, List.of(), L1);

        label.set(new PromptBundleSelection("v2.0", PromptBundleSelectionSource.REGISTRY));
        SecurityDecisionStandardPromptTemplate.StructuredPrompt layer2 =
                sections.buildStructuredPrompt(event, null, null, List.of(), L2);
        SecurityDecisionStandardPromptTemplate.StructuredPrompt secondPass = sections.buildStructuredPrompt(event, null,
                null, List.of(), L2, StructuredOutputMode.VALIDATED_CONVERTER, null,
                new SecurityDecisionPromptSections.SecondPass(first.userText(), "CHALLENGE", "RETRIEVED"));

        for (SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt : List.of(first, layer2, secondPass)) {
            assertThat(prompt.systemText()).contains(LATER_SENTENCE).doesNotContain("Weigh the duty roster first.");
            assertThat(prompt.executionMetadata().supplementalMetadata())
                    .containsEntry(PromptExecutionMetadata.PROMPT_VERSION_NAME, "v3.0")
                    .containsEntry(PromptExecutionMetadata.PROMPT_CONTENT_HASH, LATER_PRODUCT.contentHash())
                    .containsEntry("promptBundleSelectionSource", "REGISTRY");
        }
        // The correction asks again in the words of the version the decision runs (the strategy hands it to the call).
        assertThat(template.promptVersion(event)).isEqualTo(LATER_PRODUCT);
        assertThat(template.promptVersion(event).correction(SecurityDecisionPromptDocument.CORRECTION_CONTRACT,
                Map.of("violation", "X", "keys", "action"))).startsWith(LATER_CORRECTION);
        // A judgement again is a new attempt with the event's metadata: it runs the same version.
        SecurityEvent again = SecurityEvent.builder().eventId("event-pin-1-again-1").userId("alice")
                .metadata(new LinkedHashMap<>(event.getMetadata())).build();
        assertThat(template.promptVersion(again)).isEqualTo(LATER_PRODUCT);
        assertThat(sections.buildStructuredPrompt(again, null, null, List.of(), L1).systemText()).contains(LATER_SENTENCE);

        // The next decision runs where the label points now.
        SecurityEvent next = event("event-pin-2");
        assertThat(sections.buildStructuredPrompt(next, null, null, List.of(), L1).systemText())
                .contains("Weigh the duty roster first.").doesNotContain(LATER_SENTENCE);
        assertThat(next.getMetadata())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION, "v2.0")
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH, ORGANIZATION.contentHash());
    }

    @Test
    void aCopyThatNamesAnotherVersionStatesThatVersionsContentHash() {
        SecurityDecisionPromptSections sections = sections();
        SecurityEvent event = event("event-pin-3");
        sections.bundleOf(event);
        // A shadow run's copy is taken before the decision fixes its version and names its candidate; a copy that still
        // carries a content hash of another version states the hash of the version it names.
        Map<String, Object> copied = new LinkedHashMap<>(event.getMetadata());
        copied.put(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION, "v2.0");
        copied.put(SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE, PromptBundleSelectionSource.SHADOW.name());
        SecurityEvent shadow = SecurityEvent.builder().eventId("event-pin-3:shadow").userId("alice").metadata(copied)
                .build();

        assertThat(sections.promptVersionOf(shadow)).isEqualTo(ORGANIZATION);
        assertThat(shadow.getMetadata())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH, ORGANIZATION.contentHash());
        assertThat(event.getMetadata())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH, LATER_PRODUCT.contentHash());
    }

    @Test
    void aVersionTheStoreCannotFindRunsTheProductAndIsReportedOnce(CapturedOutput output) {
        label.set(new PromptBundleSelection("v9.0", PromptBundleSelectionSource.CONFIGURATION));
        SecurityDecisionPromptSections sections = sections();

        SecurityEvent first = event("event-pin-4");
        String systemText = sections.buildStructuredPrompt(first, null, null, List.of(), L1).systemText();
        sections.buildStructuredPrompt(event("event-pin-5"), null, null, List.of(), L1);

        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        assertThat(systemText).doesNotContain(LATER_SENTENCE).doesNotContain("Weigh the duty roster first.");
        assertThat(first.getMetadata())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION, product.release())
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE, "BUILD_DEFAULT")
                .containsEntry(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH, product.contentHash());
        assertThat(output.getOut().split("Prompt version v9.0 chosen by CONFIGURATION cannot be found", -1))
                .as("reported once").hasSize(2);
    }

    private static SecurityEvent event(String eventId) {
        return SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.parse("2026-11-17T03:17:00Z"))
                .userId("alice")
                .sessionId("session-pin")
                .sourceIp("10.0.0.1")
                .build();
    }
}
