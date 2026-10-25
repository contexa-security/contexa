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
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector.Inspection;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The v21 response check (V-5) on v21 prompts of the golden inputs: it asks again only for an answer without a usable
 * form or one that says what the lines do not state, and never for its action.
 */
class SecurityDecisionV21OutputInspectorTest {

    private static final String HYPOTHESES = "\"hypotheses\":[{\"id\":\"H1\",\"name\":null,\"assessment\":\"UNLIKELY\","
            + "\"for\":[\"S1\"],\"against\":[\"F1\",\"F4\"]},{\"id\":\"H2\",\"name\":null,\"assessment\":\"POSSIBLE\","
            + "\"for\":[\"F1\"],\"against\":[\"F2\"]},{\"id\":\"H3\",\"name\":null,\"assessment\":\"MOST_LIKELY\","
            + "\"for\":[\"F1\",\"F4\",\"R4\"],\"against\":[]},{\"id\":\"H4\",\"name\":null,\"assessment\":\"NO_EVIDENCE\","
            + "\"for\":[],\"against\":[]}]";

    private static final SecurityDecisionV21OutputInspector INSPECTOR = new SecurityDecisionV21OutputInspector();
    private static final Map<String, SecurityDecisionGoldenRender.RenderedCase> RENDERED = new LinkedHashMap<>();

    @BeforeAll
    static void render() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        for (JsonNode goldenCase : golden.cases()) {
            String key = goldenCase.path("caseKey").asText();
            if (key.equals("A3") || key.equals("A3T") || key.equals("S12")) {
                RENDERED.put(key, golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "ESCALATE", "BLOCK"})
    void anAnswerThatCitesWhatTheLinesStateIsKeptWhateverItsAction(String action) {
        Inspection inspection = inspect("A3", answer(action, HYPOTHESES, "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"},"
                + "{\"code\":\"NO_COVERING_RECORD\",\"fact\":\"F3\"},{\"code\":\"DATA_NATURE_MISMATCH\",\"fact\":\"R4\"}"));

        assertThat(inspection.requiresRetry()).isFalse();
        assertThat(inspection.response().getAction()).isEqualTo(action);
    }

    @Test
    void aCitationOfAnIdThePromptDoesNotGiveIsAskedAgain() {
        Inspection inspection = inspect("A3", answer("BLOCK", HYPOTHESES, "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F99\"}"));

        assertThat(inspection.requiresRetry()).isTrue();
        assertThat(inspection.retryReason()).contains("REASON_CODE_MISMATCH").contains("F99");
    }

    @Test
    void aDifferenceTheComparisonDoesNotStateIsAskedAgain() {
        // A3's network is the usual one (SameAsBaseline); the differences line does not name it.
        Inspection inspection = inspect("A3", answer("CHALLENGE", HYPOTHESES,
                "{\"code\":\"DEVIATION_NETWORK\",\"fact\":\"F1\"}"));

        assertThat(inspection.requiresRetry()).isTrue();
        assertThat(inspection.retryReason()).contains("DEVIATION_NETWORK F1");
    }

    @Test
    void aDecisionTimeIsReadAsTheApprovalLineStatesIt() {
        // A3T: the approval's decision time is not recorded; S12: it was decided 20 minutes after the request.
        Inspection notRecorded = inspect("A3T", answer("ALLOW", HYPOTHESES,
                "{\"code\":\"RECORD_DECIDED_AFTER_REQUEST\",\"fact\":\"F4\"}"));
        Inspection late = inspect("S12", answer("ESCALATE", HYPOTHESES,
                "{\"code\":\"RECORD_DECIDED_AFTER_REQUEST\",\"fact\":\"F4\"}"));
        Inspection covers = inspect("A3T", answer("ALLOW", HYPOTHESES,
                "{\"code\":\"RECORD_COVERS_WORK\",\"fact\":\"F4\"}"));

        assertThat(notRecorded.requiresRetry()).isTrue();
        assertThat(late.requiresRetry()).isFalse();
        // Whether the approval covers the work is the model's judgment of the line.
        assertThat(covers.requiresRetry()).isFalse();
    }

    @Test
    void anAnswerWithoutExplanationsOrWithAnExplanationCitingNoFactIsAskedAgain() {
        Inspection none = inspect("A3", "{\"action\":\"BLOCK\",\"reasonCodes\":[{\"code\":\"DEVIATION_TIME\","
                + "\"fact\":\"F1\"}],\"reason\":\"r\",\"riskScore\":null,\"confidence\":null,\"mitre\":null}");
        Inspection unknownFact = inspect("A3", answer("BLOCK", "\"hypotheses\":[{\"id\":\"H3\",\"name\":null,"
                + "\"assessment\":\"MOST_LIKELY\",\"for\":[\"F42\"],\"against\":[]}]",
                "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}"));

        assertThat(none.retryReason()).contains("HYPOTHESES_MISSING");
        assertThat(unknownFact.retryReason()).contains("HYPOTHESIS_MISMATCH").contains("F42");
    }

    /**
     * RL-4: a code that cites a line that exists but that it may not cite, or whose measured fact does not state what the
     * code says, is the only fault of an answer the step keeps; a code or a line the answer made up, a missing code or
     * explanation, or a sound answer, is not.
     */
    @Test
    void onlyCodesThatCiteAnExistingLineTheyMayNotCiteAreFaultsToKeepTheAnswerWith() {
        SecurityDecisionV21OutputInspector.V21Inspection unsupported = inspectFull("A3", answer("CHALLENGE", HYPOTHESES,
                "{\"code\":\"DEVIATION_NETWORK\",\"fact\":\"F1\"}"));
        SecurityDecisionV21OutputInspector.V21Inspection madeUpLine = inspectFull("A3", answer("BLOCK", HYPOTHESES,
                "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F99\"}"));
        SecurityDecisionV21OutputInspector.V21Inspection madeUpCode = inspectFull("A3", answer("BLOCK", HYPOTHESES,
                "{\"code\":\"NOT_A_REAL_CODE\",\"fact\":\"F1\"}"));
        SecurityDecisionV21OutputInspector.V21Inspection noExplanations = inspectFull("A3",
                "{\"action\":\"CHALLENGE\",\"reasonCodes\":[{\"code\":\"DEVIATION_NETWORK\",\"fact\":\"F1\"}],"
                        + "\"reason\":\"r\",\"riskScore\":null,\"confidence\":null,\"mitre\":null}");
        SecurityDecisionV21OutputInspector.V21Inspection noCodes = inspectFull("A3", answer("ALLOW", HYPOTHESES, ""));
        SecurityDecisionV21OutputInspector.V21Inspection sound = inspectFull("A3", answer("ALLOW", HYPOTHESES,
                "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}"));

        assertThat(unsupported.inspection().requiresRetry()).isTrue();
        assertThat(unsupported.inspection().retryReason()).contains("REASON_CODE_MISMATCH").contains("DEVIATION_NETWORK F1");
        assertThat(unsupported.unsupportedCodesOnly()).isTrue();
        assertThat(madeUpLine.unsupportedCodesOnly()).isFalse();
        assertThat(madeUpCode.unsupportedCodesOnly()).isFalse();
        assertThat(noExplanations.inspection().retryReason()).contains("REASON_CODE_MISMATCH").contains("HYPOTHESES_MISSING");
        assertThat(noExplanations.unsupportedCodesOnly()).isFalse();
        assertThat(noCodes.unsupportedCodesOnly()).isFalse();
        assertThat(sound.inspection().requiresRetry()).isFalse();
        assertThat(sound.unsupportedCodesOnly()).isFalse();
    }

    @Test
    void anAnswerWithoutAUsableFormIsATechnicalFailure() {
        Inspection inspection = inspect("A3", "the request looks risky");

        assertThat(inspection.parsingFallback()).isTrue();
        assertThat(inspection.retryReason()).startsWith("PARSER_");
    }

    @Test
    void theExplanationsOfTheAnswerAreKeptForTheRecord() {
        SecurityDecisionGoldenRender.RenderedCase item = RENDERED.get("A3");
        SecurityDecisionV21OutputInspector.V21Inspection inspection = INSPECTOR.inspect(
                answer("ESCALATE", HYPOTHESES, "{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}"), "r-1", "initial",
                new SecurityDecisionV21OutputInspector.V21Check(item.canonicalContext(), item.userText()));

        assertThat(inspection.hypotheses()).hasSize(4);
        assertThat(inspection.hypotheses().get(2)).containsEntry("id", "H3").containsEntry("assessment", "MOST_LIKELY");
    }

    private static Inspection inspect(String caseKey, String raw) {
        return inspectFull(caseKey, raw).inspection();
    }

    private static SecurityDecisionV21OutputInspector.V21Inspection inspectFull(String caseKey, String raw) {
        SecurityDecisionGoldenRender.RenderedCase item = RENDERED.get(caseKey);
        return INSPECTOR.inspect(raw, "r-1", "initial",
                new SecurityDecisionV21OutputInspector.V21Check(item.canonicalContext(), item.userText()));
    }

    private static String answer(String action, String hypotheses, String reasonCodes) {
        return "{\"action\":\"" + action + "\"," + hypotheses + ",\"reasonCodes\":[" + reasonCodes + "],"
                + "\"reason\":\"The owner exports a project outside their work at night.\",\"riskScore\":0.7,"
                + "\"confidence\":0.6,\"mitre\":null}";
    }
}
