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
            "{\"action\":\"ALLOW|CHALLENGE|ESCALATE|BLOCK\"}";

    private static final String JSON_SCHEMA = """
            {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"action":{"type":"string","enum":["ALLOW","CHALLENGE","ESCALATE","BLOCK"]},"reasoning":{"type":"string"},"mitre":{"type":"string"},"riskScore":{"type":"number","minimum":0.0,"maximum":1.0},"confidence":{"type":"number","minimum":0.0,"maximum":1.0},"evidenceRefs":{"type":"array","items":{"type":"string"}}},"required":["action"],"additionalProperties":false}
            """.trim();

    static String formatInstructions() {
        return """
                Your response should be in JSON format.
                Return one RFC8259 compliant JSON object without explanations or markdown.
                The response must satisfy this JSON Schema:
                ```%s```
                """.formatted(JSON_SCHEMA);
    }

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        return template.buildDecisionSection(context.getStructuredOutputMode());
    }
}
