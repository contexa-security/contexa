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

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bundle v21.13 (docs/agent B3-3): the validated case memory's lines that hold stored free text (an earlier analysis'
 * summary, a threat signal's summary, matched threat knowledge) leave the ValidatedCases line, and the UNTRUSTED TEXT
 * block quotes each of their texts once; the counts and states stay. The v20 render is unchanged, and the inspector
 * compares the quoted texts with the sealed reasoning memory.
 */
class V21ValidatedCaseMemoryTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);
    private static final SecurityDecisionGoldenRender GOLDEN = SecurityDecisionGoldenRender.load();

    private static final String OBJECTIVE_MEMORY = "Objective-aware reasoning memory spans REPORTING.";
    private static final String XAI_FACT = "XAI on a local EXPORT case highlighted: export size above the owner's usual";
    private static final String REASONING_FACT = "Retention tier is HOT.";
    private static final String CROSS_TENANT_FACT = "Signal sig-7 spans 3 tenants for objective families REPORTING.";

    @Test
    void aV21RenderQuotesTheStoredMemoryTextsAndKeepsTheCountsOnTheValidatedCasesLine() {
        InspectionGolden.Render v21 = render(SecurityDecisionPromptBundles.V21);

        String cases = value(v21.userPrompt(), "ValidatedCases");
        assertThat(cases).contains("ReinforcedCaseCount: 3", "HardNegativeCaseCount: 1", "RetentionTier: HOT");
        assertThat(cases).doesNotContain("ObjectiveAwareReasoningMemory", "XaiLinkedFacts", "ReasoningFacts",
                "CrossTenantObjectiveMisuseFacts", "XAI on a local", "sig-7");
        // Each stored text once, in the memory section's order: the reasoning fact that repeats the objective memory
        // is quoted once.
        assertThat(memoryLines(v21.userPrompt())).containsExactly(
                quoted(OBJECTIVE_MEMORY), quoted(XAI_FACT), quoted(REASONING_FACT), quoted(CROSS_TENANT_FACT));

        PromptInspectionResult result = INSPECTOR.inspect(v21.sealed());
        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .extracting(PromptInspectionFinding::entry).isEmpty();
    }

    @Test
    void theV20RenderKeepsTheMemoryTextsOnTheValidatedCasesLine() {
        InspectionGolden.Render v20 = render(SecurityDecisionPromptBundles.V20);

        assertThat(value(v20.userPrompt(), "ValidatedCases")).contains("ReinforcedCaseCount: 3",
                "ObjectiveAwareReasoningMemory: " + OBJECTIVE_MEMORY, "XaiLinkedFacts: " + XAI_FACT,
                "CrossTenantObjectiveMisuseFacts: " + CROSS_TENANT_FACT);
        assertThat(v20.userPrompt()).doesNotContain(UntrustedTextSources.VALIDATED_CASE_MEMORY);
    }

    @Test
    void theInspectorPointsAtAQuotedMemoryTextTheSealedMemoryDoesNotHold() {
        InspectionGolden.Render v21 = render(SecurityDecisionPromptBundles.V21);
        String line = Arrays.stream(v21.userPrompt().split("\n"))
                .filter(each -> each.contains(quoted(XAI_FACT))).findFirst().orElseThrow();
        InspectionGolden.Render tampered = new InspectionGolden.Render(v21.caseKey(), v21.profile(),
                v21.systemPrompt(), v21.userPrompt().replace(line, line.replace(XAI_FACT, "FORGED memory text")),
                v21.used(), v21.executionMetadata(), v21.ragResultsJson(), v21.requestFactsJson());

        PromptInspectionResult result = INSPECTOR.inspect(tampered.sealed());

        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .anyMatch(finding -> finding.actual() != null && finding.actual().contains("FORGED memory text"));
    }

    /** The first golden case with a reasoning memory whose free text lines hold the texts above. */
    private static InspectionGolden.Render render(SecurityDecisionPromptBundles.Bundle bundle) {
        ObjectNode goldenCase = GOLDEN.cases().get(0).deepCopy();
        ObjectNode canonical = (ObjectNode) goldenCase.path("canonicalContext");
        ObjectNode memory = canonical.putObject("reasoningMemoryProfile");
        memory.put("reinforcedCaseCount", 3);
        memory.put("hardNegativeCaseCount", 1);
        memory.put("retentionTier", "HOT");
        memory.put("objectiveAwareReasoningMemory", OBJECTIVE_MEMORY);
        memory.putArray("xaiLinkedFacts").add(XAI_FACT);
        memory.putArray("reasoningFacts").add(OBJECTIVE_MEMORY).add(REASONING_FACT);
        memory.putArray("crossTenantObjectiveMisuseFacts").add(CROSS_TENANT_FACT);

        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        SecurityDecisionGoldenRender.RenderedCase rendered = GOLDEN.render(goldenCase,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        return new InspectionGolden.Render(rendered.caseKey(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                rendered.systemText(), rendered.userText(), rendered.canonicalContext(),
                rendered.executionMetadata().toMetadataMap(), goldenCase.path("ragResults").toString(),
                goldenCase.path("requestFacts").toString());
    }

    private static String quoted(String text) {
        return "source=" + UntrustedTextSources.VALIDATED_CASE_MEMORY + "; \"" + text.replace("\"", "\\\"") + "\"";
    }

    /** The UNTRUSTED TEXT values that quote the validated case memory, their fact ids and labels set aside. */
    private static List<String> memoryLines(String userPrompt) {
        return Arrays.stream(userPrompt.split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.matches("UntrustedText\\d+: .*"))
                .map(line -> line.substring(line.indexOf(": ") + 2))
                .filter(value -> value.startsWith("source=" + UntrustedTextSources.VALIDATED_CASE_MEMORY + ";"))
                .toList();
    }

    /** The value of the first line with the label, its fact id set aside; null without one. */
    private static String value(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.startsWith(label + ": ")).findFirst()
                .map(line -> line.substring(label.length() + 2)).orElse(null);
    }
}
