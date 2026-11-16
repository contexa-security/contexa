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
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-2 (decision D6): the functions of the measured v1.0 variants are versions of v1.0, so the variant bundles can go
 * without a function lost. A version that includes the prepared decision rules states the conclusion lines the fallback
 * variants stated, word for word, every rule they stated, and replaces an answer that still breaks one (their fallback);
 * the record variant is the product version; a version without the similar case reading runs no similarity search, as
 * the exact variants ran none.
 */
class PreparedPartsEquivalenceTest {

    private static final String V2 = "v2.0";
    private final PromptAssembler assembler = new PromptAssembler();

    private AssembledPrompt version(String body) {
        return assembler.apply(SecurityDecisionPromptDocument.product(), new PromptVersionDocumentReader()
                .read("prompt: cortex.security-decision\nbasedOn: v1.0\ntitle: Prepared parts\n" + body));
    }

    private static PromptVersionStore storeOf(AssembledPrompt version) {
        return (prompt, name) -> V2.equals(name) ? Optional.of(version) : Optional.empty();
    }

    private static final String WITH_RULES = """
            system:
              - key: decision-rules
                include: true
            """;

    @Test
    void aVersionWithTheDecisionRulesStatesTheConclusionLinesOfTheFallbackVariantWordForWord() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        PromptVersionStore store = storeOf(version(WITH_RULES));
        TieredStrategyProperties variant = active(SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR);
        TieredStrategyProperties product = active(SecurityDecisionPromptBundles.V1);
        int compared = 0;
        for (JsonNode goldenCase : golden.cases()) {
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                String before = golden.render(goldenCase, profile, variant).userText();
                String now = golden.renderVersion(goldenCase, profile, product, store, V2, Map.of()).userText();
                assertThat(now).as(goldenCase.path("caseKey").asText() + "/" + profile).isEqualTo(before);
                compared++;
            }
        }
        assertThat(compared).isEqualTo(golden.cases().size() * 2);
        assertThat(golden.render(golden.cases().get(0), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, variant)
                .userText()).contains("DeviationsExplained: ");
    }

    @Test
    void theRecordVariantsUserPromptIsTheProductVersionsUserPrompt() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties variant = active(SecurityDecisionPromptBundles.V1_RECORD_SIMILAR);
        TieredStrategyProperties product = active(SecurityDecisionPromptBundles.V1);
        for (JsonNode goldenCase : golden.cases()) {
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                assertThat(golden.render(goldenCase, profile, product).userText())
                        .as(goldenCase.path("caseKey").asText() + "/" + profile)
                        .isEqualTo(golden.render(goldenCase, profile, variant).userText());
            }
        }
    }

    @Test
    void aVersionWithTheDecisionRulesStatesEveryRuleTheFallbackVariantStated() {
        String rules = version(WITH_RULES).draw(AssembledPrompt.JUDGMENT, Set.of(), null);
        String agent = version(WITH_RULES).draw(AssembledPrompt.JUDGMENT,
                Set.of(SecurityDecisionPromptDocument.AGENT_REQUEST), null);
        List<String> variantRules = SecurityDecisionPromptSections.V1_DECISION_RULES.lines()
                .filter(line -> !line.startsWith("* Verified signal boundary:")).toList();

        assertThat(variantRules).hasSize(9);
        variantRules.forEach(line -> assertThat(rules).as("the rule line").contains(line));
        assertThat(agent).doesNotContain(SecurityDecisionPromptSections.V20_AUTOMATION_BOUNDARY.strip())
                .doesNotContain(SecurityDecisionPromptSections.V20_AUTOMATION_CATEGORY.strip())
                .contains("Decision rules (they come before the judgment above");
        assertThat(rules.indexOf("Decision rules (")).isGreaterThan(rules.indexOf("Responses and what they do:"))
                .isLessThan(rules.indexOf("Honesty:"));
        assertThat(SecurityDecisionVersionFeatures.of(version(WITH_RULES)))
                .isEqualTo(new SecurityDecisionVersionFeatures(true, true, true, true, true));
    }

    @Test
    void theVerifiedSignalBoundaryIsAParagraphOfItsOwnAndTheFloorsComeOnlyWhenTheHostEnforcesThem() {
        AssembledPrompt both = version("""
                system:
                  - key: decision-rules
                    include: true
                  - key: verified-signal-boundary
                    include: true
                """);
        String variantSignal = SecurityDecisionPromptSections.V1_DECISION_RULES.lines()
                .filter(line -> line.startsWith("* Verified signal boundary:")).findFirst().orElseThrow();
        SecurityDecisionPromptSections observe = sections(both, "OBSERVE");
        SecurityDecisionPromptSections enforce = sections(both, "ENFORCE");
        String observed = observe.buildSystemInstructionV1(contextOf(), SecurityDecisionPromptBundles.V1.features());
        String enforced = enforce.buildSystemInstructionV1(contextOf(), SecurityDecisionPromptBundles.V1.features());

        assertThat(observed).contains("\n\n" + variantSignal.substring(2) + "\n").doesNotContain("Minimum action rules");
        assertThat(enforced).contains("Minimum action rules: the host sets the weakest response allowed");
    }

    @Test
    void aVersionWithoutTheSimilarCaseReadingRunsNoSimilaritySearch() {
        AssembledPrompt exact = version("""
                system:
                  - key: similar-case-reading
                    delete: true
                  - key: similar-case-limits
                    delete: true
                """);

        assertThat(SecurityDecisionVersionFeatures.of(SecurityDecisionPromptDocument.product()).similarCases()).isTrue();
        assertThat(SecurityDecisionVersionFeatures.of(exact).similarCases()).isFalse();
        assertThat(exact.draw(AssembledPrompt.JUDGMENT, Set.of(), null)).doesNotContain("SimilarCase");
    }

    private static TieredStrategyProperties active(SecurityDecisionPromptBundles.Bundle bundle) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        return properties;
    }

    private static SecurityDecisionPromptSections sections(AssembledPrompt version, String mode) {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                new TieredStrategyProperties(), event -> Optional.empty(), new PromptContextComposer());
        sections.setPromptVersionStore(storeOf(version));
        sections.setMinimumActionSettings(MinimumActionRules.Settings.DEFAULTS, mode);
        return sections;
    }

    private static SecurityPromptBuildContext contextOf() {
        SecurityEvent event = SecurityEvent.builder().eventId("prepared-parts").metadata(new LinkedHashMap<>()).build();
        event.addMetadata(SecurityDecisionPromptDocument.EVENT_PROMPT_VERSION, V2);
        return new SecurityPromptBuildContext(event, null, null, List.of(), null, null, null, null, null, null, null);
    }
}
