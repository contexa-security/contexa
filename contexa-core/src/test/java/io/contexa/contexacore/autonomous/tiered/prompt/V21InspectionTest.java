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

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sealed packages of the decisions the product version draws, read by the prompt inspector (V-6 of the v21 plan, the
 * v21 lines v1.0 keeps): every golden case's L1 package is read as a dictionary prompt with the v1.0 records dictionary,
 * its decision facts computed again in the records notation, and its reason codes checked against the output contract
 * v4; none says other than its sources.
 */
class V21InspectionTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);

    @Test
    void everyGoldenPackageIsReadWithTheV1RecordsDictionaryAndSaysNothingElseThanItsSources() {
        assertThat(InspectionGolden.v21Renders()).hasSize(27);
        for (InspectionGolden.Render render : InspectionGolden.v21Renders()) {
            PromptInspectionResult result = INSPECTOR.inspect(render.sealed());

            assertThat(result.layoutVersion()).as(render.caseKey()).isEqualTo(PromptInspector.V1_LAYOUT);
            // The product version states the records, not the conclusions of the decision rules (D6).
            assertThat(result.dictionaryVersion()).as(render.caseKey()).isEqualTo(PromptInspector.V1_DICTIONARY_VERSION);
            assertThat(result.verdict()).as(render.caseKey() + " " + mismatches(result))
                    .isIn(PromptInspectionVerdict.PASS, PromptInspectionVerdict.INCOMPLETE);
            assertThat(result.matchedCount()).as(render.caseKey()).isPositive();
        }
    }

    @Test
    void theReasonCodesOfADecisionAreCheckedAgainstTheOutputContractV4() {
        InspectionGolden.Render a3 = InspectionGolden.v21Renders().stream()
                .filter(render -> render.caseKey().equals("A3")).findFirst().orElseThrow();

        PromptInspectionResult cited = INSPECTOR.inspect(withDecision(a3.sealed(),
                "{\"action\":\"ESCALATE\",\"reasonCodes\":[{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"},"
                        + "{\"code\":\"NO_COVERING_RECORD\",\"fact\":\"F3\"}]}"));
        PromptInspectionResult wrong = INSPECTOR.inspect(withDecision(a3.sealed(),
                "{\"action\":\"ESCALATE\",\"reasonCodes\":[{\"code\":\"DEVIATION_NETWORK\",\"fact\":\"F1\"}]}"));

        assertThat(cited.verdict()).isIn(PromptInspectionVerdict.PASS, PromptInspectionVerdict.INCOMPLETE);
        assertThat(wrong.verdict()).isEqualTo(PromptInspectionVerdict.FAIL);
        assertThat(wrong.findings()).extracting(PromptInspectionFinding::entry).contains("DEVIATION_NETWORK");
    }

    private static SealedEvidencePackage withDecision(SealedEvidencePackage sealed, String decisionJson) {
        sealed.setDecisionJson(decisionJson);
        sealed.setPackageHash(new SealedEvidencePackageIntegrity().computeHash(sealed));
        return sealed;
    }

    private static List<String> mismatches(PromptInspectionResult result) {
        return result.findings().stream().filter(finding -> finding.expected() != null || finding.actual() != null)
                .map(finding -> finding.block() + "." + finding.entry() + ": " + finding.reason()).limit(6).toList();
    }
}
