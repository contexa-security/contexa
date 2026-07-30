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

public class SecurityDecisionContractSectionBuilder implements SecurityPromptSectionBuilder {

    static final String MINIMAL_RESPONSE_EXAMPLE =
            "{\"action\":\"ALLOW|CHALLENGE|ESCALATE|BLOCK\",\"reasoning\":\"one concise evidence-based sentence\"}";

    private static final String JSON_SCHEMA = """
            {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"action":{"type":"string","enum":["ALLOW","CHALLENGE","ESCALATE","BLOCK"]},"reasoning":{"type":"string","maxLength":180},"mitre":{"type":"string"},"riskScore":{"type":"number","minimum":0.0,"maximum":1.0},"confidence":{"type":"number","minimum":0.0,"maximum":1.0},"evidenceRefs":{"type":"array","items":{"type":"string"}}},"required":["action","reasoning"],"additionalProperties":false}
            """.trim();

    static String formatInstructions() {
        return """
                Your response should be in JSON format.
                Return one RFC8259 compliant JSON object without explanations or markdown.
                The response must satisfy this JSON Schema:
                ```%s```
                Final wording check: decide action first. For ALLOW with SAME_RESOURCE authorized RAG, copy the matching exact system-contract sentence for the current PersonalBaselineEstablished value; never assert an established baseline when it is false or absent.
                """.formatted(JSON_SCHEMA);
    }

    static String runtimeReasoningGate() {
        return "FINAL RESPONSE COMPACTNESS - use at most 20 words and 140 characters; "
                + "never exceed 25 words or 180 characters; "
                + "before using fresh-verification wording, confirm the current request explicitly has VerificationRequired=true; "
                + "MfaVerified=false or weak baseline evidence must not create that fact; "
                + "copy any matching exact system-contract sentence verbatim without paraphrasing.";
    }

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildDecisionSection(context.getStructuredOutputMode());
    }
}
