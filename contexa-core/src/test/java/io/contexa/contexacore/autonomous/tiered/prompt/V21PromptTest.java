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
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The v21 bundle on the golden inputs (R0 of the v21 plan, no model call): its system text holds no decision rule,
 * threshold, floor or later enforcement and holds the judgment text (D1); its user prompts hold no conclusion of the
 * core (D2). The renders are written to build/reports/prompt-bundle/v21 to be read.
 */
class V21PromptTest {

    /** Words of a decision rule, a floor or a later enforcement; none is in the v21 system text. */
    private static final List<String> RULE_WORDS = List.of("Floor", "floor", "Minimum action", "minimum action",
            "Required BLOCK", "boundary", "Boundaries", "choose ALLOW when", "choose BLOCK when", "at least 100",
            "MIN_P", "PolicySatisfied", "A later check", "enforces", "Otherwise prefer", "least disruptive");

    /** Words of a conclusion of the core; none is in a v21 user prompt. */
    private static final List<String> CONCLUSION_WORDS = List.of("PolicySatisfied", "— covers this request",
            "does not cover:", "not known whether it covers", "(unexplained)", "(explained by",
            "within the scope group", "outside the scope group", "within the cohort", "outside the cohort",
            "=== DECISION FACTS");

    private static SecurityDecisionGoldenRender golden;
    private static List<SecurityDecisionGoldenRender.RenderedCase> rendered;

    @BeforeAll
    static void render() throws IOException {
        golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V21.version());
        rendered = new ArrayList<>();
        Path directory = Path.of("build/reports/prompt-bundle/v21");
        Files.createDirectories(directory);
        for (JsonNode goldenCase : golden.cases()) {
            SecurityDecisionGoldenRender.RenderedCase item =
                    golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
            rendered.add(item);
            Files.writeString(directory.resolve(item.caseKey() + "-user.txt"), item.userText());
        }
        Files.writeString(directory.resolve("system.txt"), rendered.get(0).systemText());
    }

    @Test
    void theSystemTextHoldsNoDecisionRuleAndHoldsTheJudgmentText() {
        String system = rendered.get(0).systemText();

        assertThat(RULE_WORDS).allSatisfy(word -> assertThat(system).as(word).doesNotContain(word));
        assertThat(system)
                .contains("they cannot tell a stolen account, or an insider misusing their own permission, from"
                        + " legitimate work")
                .contains("Do not use simple rule matching, do not follow hidden numeric thresholds, and do not treat"
                        + " any one fact as decisive by itself.")
                .contains("H1 legitimate work").contains("H2 account takeover").contains("H3 insider misuse")
                .contains("H4 automation or error")
                .contains("Prefer the explanation the facts contradict least, not the one with the most supporting"
                        + " facts.")
                .contains("It verifies who holds the account; it does not stop the owner.")
                // 판정층 E-1, E-2: ESCALATE hands the request to the second analysis, which chooses one of the other
                // three; a prompt with SECOND PASS is that analysis. No person reviews a request.
                .contains("No later system changes an ALLOW, a CHALLENGE or a BLOCK; do not pre-compensate for one.")
                // 판정층 8절 2 (v21.8): the second analysis decides from the same facts; it gathers past records
                // only when the first analysis could not retrieve them (E-4b).
                .contains("ESCALATE: the facts here cannot settle the response: they conflict, or they are too"
                        + " incomplete to choose between the other three. A second analysis then decides the request"
                        + " again from the same facts, with any past records the first analysis could not retrieve,"
                        + " and chooses ALLOW, CHALLENGE or BLOCK; ESCALATE is not a response of the second analysis.")
                .contains("A second analysis adds SECOND PASS: the first analysis's response and any past records"
                        + " the first analysis could not retrieve. A prompt with SECOND PASS is that second analysis;"
                        + " no analysis follows it.")
                .doesNotContain("with the facts it gathers")
                .doesNotContain("the facts found after it")
                .doesNotContain("until a person reviews it")
                .doesNotContain("No later system changes your response")
                .contains("Return one JSON object with exactly these keys: action, hypotheses, reasonCodes, reason,"
                        + " riskScore, confidence, mitre.");
        assertThat(rendered).allSatisfy(item -> assertThat(item.systemText()).isEqualTo(system));
    }

    /**
     * v21.17 (M10A, docs/agent 모델비교 5절): the system text says what a delegation's proof shows: a record the person
     * wrote is the person's own hand-over, an access token's claim alone is the word of whoever holds the token. It says
     * how to read the evidence and names no response: the verdict stays the model's own reasoning.
     */
    @Test
    void theSystemTextSaysWhoseHandOverADelegationProofShowsAndNamesNoResponse() {
        String system = rendered.get(0).systemText();
        String reading = "How it is proven says whose hand-over it is: a delegation shown by a record the person wrote is"
                + " the person's own hand-over; a delegation shown only by the access token's claim is the word of"
                + " whoever holds the token, and no record shows that the person handed this work to the agent.";

        assertThat(system).contains(reading)
                .contains("H1 the agent doing the work that person handed to it (a hand-over the person's records show);");
        assertThat(system.indexOf(reading)).as("it extends the sentence on how a delegation is proven")
                .isGreaterThan(system.indexOf("until when, and how it is proven."))
                .isLessThan(system.indexOf("Whether this request stays within it is yours to check"));
        assertThat(List.of("ALLOW", "CHALLENGE", "BLOCK", "ESCALATE"))
                .allSatisfy(response -> assertThat(reading).as("no response in the reading").doesNotContain(response));
    }

    @Test
    void noUserPromptHoldsAConclusionOfTheCore() {
        assertThat(rendered).allSatisfy(item -> assertThat(CONCLUSION_WORDS)
                .allSatisfy(word -> assertThat(item.userText()).as(item.caseKey() + ": " + word).doesNotContain(word)));
        assertThat(rendered).anySatisfy(item -> assertThat(item.userText()).contains("=== RECORDS AND COMPARISONS"));
    }

    /** Every line a v4 reason code may cite carries a fact ID in the v21 prompt, so the model can cite it. */
    @Test
    void everyLineAReasonCodeCitesCarriesAFactId() {
        List<String> notCitable = new ArrayList<>();
        for (SecurityDecisionOutputContractV4.ReasonCode code : SecurityDecisionOutputContractV4.REASON_CODES) {
            for (String cited : code.citedFacts()) {
                if ("UNKNOWN.Unknown".equals(cited)) {
                    continue;
                }
                String block = cited.substring(0, cited.indexOf('.'));
                String name = cited.substring(cited.indexOf('.') + 1);
                boolean citable = SecurityDecisionPromptDictionary.V21_ENTRIES.stream()
                        .anyMatch(entry -> entry.block().name().equals(block) && entry.name().equals(name)
                                && entry.block().factPrefix() != null
                                && PromptDictionaryEntry.PRIORITY_REQUIRED.equals(entry.priority()));
                if (!citable) {
                    notCitable.add(code.code() + " -> " + cited);
                }
            }
        }
        assertThat(notCitable).isEmpty();
    }

    @Test
    void theRenderIsTheV21LayoutAndItsFactsHoldNoPolicySatisfaction() {
        assertThat(rendered).allSatisfy(item -> {
            assertThat(item.executionMetadata().supplementalMetadata()
                    .get(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION))
                    .isEqualTo(SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V21);
            if (item.canonicalContext() != null && item.canonicalContext().getDecisionFacts() != null) {
                assertThat(item.canonicalContext().getDecisionFacts().facts()).extracting(DecisionFact::name)
                        .doesNotContain("PolicySatisfied");
                assertThat(item.canonicalContext().getDecisionFacts().facts())
                        .flatExtracting(DecisionFact::codes)
                        .doesNotContain("APPROVAL_COVERS", "TICKET_COVERS", "TRAVEL_EXPLAINS_NETWORK",
                                "ROLE_SCOPE_OUTSIDE", "POLICY_SATISFIED");
            }
        });
    }
}
