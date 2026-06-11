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
package io.contexa.contexacore.std.components.prompt;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class PromptFieldPolicyCatalogTest {

    @Test
    void resolvesPromptFieldsFromExplicitSectionRules() {
        PromptFieldPolicy requestPolicy = PromptFieldPolicyCatalog.resolve(
                "final_user_prompt_field:CURRENT_REQUEST_AND_EVENT.User",
                "FINAL_USER_PROMPT_FIELD",
                "userPrompt.CURRENT_REQUEST_AND_EVENT.User",
                "User");

        assertThat(requestPolicy.qualityRelevance()).isEqualTo(PromptFieldPolicyCatalog.LLM_DECISION_CONTRACT);
        assertThat(requestPolicy.metricCodes()).contains("CCR", "CCSR", "EIR");
        assertThat(requestPolicy.remediationOwner()).isEqualTo("REQUEST_CONTEXT_PRODUCER");

        PromptFieldPolicy baselinePolicy = PromptFieldPolicyCatalog.resolve(
                "final_user_prompt_field:PERSONAL_WORK_PROFILE.BaselineObservations",
                "FINAL_USER_PROMPT_FIELD",
                "userPrompt.PERSONAL_WORK_PROFILE.BaselineObservations",
                "BaselineObservations");

        assertThat(baselinePolicy.metricCodes()).contains("BMA", "USNS");
        assertThat(baselinePolicy.remediationOwner()).isEqualTo("BASELINE_CONTEXT_PRODUCER");
    }

    @Test
    void resolvesSourceFieldsFromExplicitSourcePathRules() {
        PromptFieldPolicy sourcePolicy = PromptFieldPolicyCatalog.resolve(
                "source:securityEvent.metadata.requestPath",
                "SOURCE_CONTEXT",
                "securityEvent.metadata.requestPath",
                null);

        assertThat(sourcePolicy.qualityRelevance()).isEqualTo(PromptFieldPolicyCatalog.LLM_DECISION_CONTRACT);
        assertThat(sourcePolicy.metricCodes()).contains("CCR", "CCSR", "EIR");
        assertThat(sourcePolicy.remediationOwner()).isEqualTo("REQUEST_CONTEXT_PRODUCER");
    }

    @Test
    void catalogDoesNotUseSubstringGuessingHelpers() throws Exception {
        String source = Files.readString(Path.of(
                "src/main/java/io/contexa/contexacore/std/components/prompt/PromptFieldPolicyCatalog.java"));

        assertThat(source).doesNotContain("containsAny");
        assertThat(source).doesNotContain(".contains(");
    }
}
