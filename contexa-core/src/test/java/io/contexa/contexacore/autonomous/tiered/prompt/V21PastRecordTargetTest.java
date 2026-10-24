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
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bundle v21.11 (docs/agent A3-5): a past record's target is the path variables a requester wrote, so a v21 past record
 * line writes it apart and the UNTRUSTED TEXT block quotes it; the same-target field stays the core's comparison. The
 * v20 render is unchanged, and the inspector compares the v21 lines with the sealed records.
 */
class V21PastRecordTargetTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);

    @Test
    void aV21PastRecordLineWritesItsTargetApartAndTheUntrustedTextQuotesIt() {
        Rendered rendered = firstWithATargetedPastRecord();

        List<String> recordLines = lines(rendered.v21().userPrompt(), "PastRecord");
        assertThat(recordLines).isNotEmpty().allSatisfy(line -> assertThat(line)
                .satisfiesAnyOf(value -> assertThat(value).contains(" / " + PastRecordLines.TARGET_APART + " / "),
                        value -> assertThat(value).contains(" / no target / "),
                        value -> assertThat(value).matches(".*PastRecord\\d+: \\+\\d+ more")));
        assertThat(rendered.v21().userPrompt()).contains("source=" + UntrustedTextSources.PAST_RECORD_TARGET + "; \"");
        // The v20 render writes the target as before and quotes none.
        assertThat(lines(rendered.v20().userPrompt(), "PastRecord")).noneMatch(line -> line.contains(
                PastRecordLines.TARGET_APART));
        assertThat(rendered.v20().userPrompt()).doesNotContain(UntrustedTextSources.PAST_RECORD_TARGET);

        PromptInspectionResult result = INSPECTOR.inspect(rendered.v21().sealed());
        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .extracting(PromptInspectionFinding::entry).isEmpty();
    }

    @Test
    void theInspectorPointsAtAQuotedTargetNoSealedRecordHolds() {
        Rendered rendered = firstWithATargetedPastRecord();
        String quoted = lines(rendered.v21().userPrompt(), "UntrustedText").stream()
                .filter(line -> line.contains(UntrustedTextSources.PAST_RECORD_TARGET)).findFirst().orElseThrow();
        String forged = quoted.replaceFirst("; \"(.*)\"$", "; \"projectKey=FORGED-1\"");
        InspectionGolden.Render tampered = new InspectionGolden.Render(rendered.v21().caseKey(),
                rendered.v21().profile(), rendered.v21().systemPrompt(),
                rendered.v21().userPrompt().replace(quoted, forged), rendered.v21().used(),
                rendered.v21().executionMetadata(), rendered.v21().ragResultsJson(),
                rendered.v21().requestFactsJson());

        PromptInspectionResult result = INSPECTOR.inspect(tampered.sealed());

        assertThat(result.findings()).filteredOn(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .anyMatch(finding -> finding.actual() != null && finding.actual().contains("FORGED-1"));
    }

    private record Rendered(InspectionGolden.Render v20, InspectionGolden.Render v21) {
    }

    /** The first golden case whose v21 render draws a past record with a target. */
    private static Rendered firstWithATargetedPastRecord() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        for (JsonNode goldenCase : golden.cases()) {
            Optional<Rendered> rendered = render(golden, goldenCase);
            if (rendered.isPresent()) {
                return rendered.get();
            }
        }
        throw new IllegalStateException("no golden case draws a past record with a target");
    }

    private static Optional<Rendered> render(SecurityDecisionGoldenRender golden, JsonNode goldenCase) {
        InspectionGolden.Render v21 = render(golden, goldenCase, SecurityDecisionPromptBundles.V21);
        if (lines(v21.userPrompt(), "PastRecord").stream().noneMatch(line -> line.contains(PastRecordLines.TARGET_APART))) {
            return Optional.empty();
        }
        return Optional.of(new Rendered(render(golden, goldenCase, SecurityDecisionPromptBundles.V20), v21));
    }

    private static InspectionGolden.Render render(SecurityDecisionGoldenRender golden, JsonNode goldenCase,
                                                  SecurityDecisionPromptBundles.Bundle bundle) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.render(goldenCase,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
        return new InspectionGolden.Render(rendered.caseKey(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                rendered.systemText(), rendered.userText(), rendered.canonicalContext(),
                rendered.executionMetadata().toMetadataMap(), goldenCase.path("ragResults").toString(),
                goldenCase.path("requestFacts").toString());
    }

    private static List<String> lines(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n"))
                .filter(line -> line.matches("(\\[[A-Z]\\d+\\] )?" + label + "\\d+: .*")).toList();
    }
}
