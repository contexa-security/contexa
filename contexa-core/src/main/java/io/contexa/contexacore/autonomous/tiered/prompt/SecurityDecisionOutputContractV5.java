/*
 * Copyright 2026 The Contexa Project
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *   https://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The output contract v5 (K30, 2026-11-16): the short answer of the v1.0 bundle. An answer in the contract v4 ran to
 * 600-1,000 tokens, most of them the five explanations with their lists of fact ids for and against, so a decision
 * spent most of its time writing them. The v5 answer keeps what the decision and its record use: the action, the risk
 * score, the one explanation judged most likely, one to three reason codes each citing one fact, and one short
 * sentence. The reason codes, their meanings and their citations are those of v4, so the response check reads them the
 * same way; the confidence and the MITRE ids are not asked for.
 */
public final class SecurityDecisionOutputContractV5 {

    public static final int MIN_REASON_CODES = 1;
    public static final int MAX_REASON_CODES = 3;
    /** The longest reason sentence the contract asks for, in words. */
    public static final int MAX_REASON_WORDS = 25;
    /** The keys of a v5 answer, in the order the system text names them. */
    public static final List<String> KEYS = List.of("action", "riskScore", "hypothesis", "reasonCodes", "reason");

    private static final String PROVIDER_SCHEMA = writeProviderSchema(true);
    private static final String TEXT_SCHEMA = writeProviderSchema(false);
    private static final String OUTPUT_BLOCK = writeOutputBlock();

    private SecurityDecisionOutputContractV5() {
    }

    /** The strict JSON schema for a provider with structured output: every field required, no other keys. */
    public static String providerSchema() {
        return PROVIDER_SCHEMA;
    }

    /** The schema as text for a provider without structured output; the output block states the code meanings. */
    public static String textSchema() {
        return TEXT_SCHEMA;
    }

    /** The output block of the v1.0 system text: the fields, how a code cites a fact and the meaning of every code. */
    public static String systemOutputBlock() {
        return OUTPUT_BLOCK;
    }

    private static String writeOutputBlock() {
        StringBuilder block = new StringBuilder();
        block.append("=== OUTPUT ===\n");
        block.append("Return one compact JSON object, on one line, with exactly these keys: ")
                .append(String.join(", ", KEYS)).append(".\n");
        block.append("action: ALLOW, CHALLENGE, ESCALATE or BLOCK.\n");
        block.append("riskScore: a number from 0 to 1, kept for audit.\n");
        block.append("hypothesis: the id of the explanation you judged most likely: H1, H2, H3, H4 or H5.\n");
        block.append("reasonCodes: ").append(MIN_REASON_CODES).append(" to ").append(MAX_REASON_CODES)
                .append(" objects {\"code\": ..., \"fact\": ...} for the facts that weigh most in your judgment, first the"
                        + " strongest, each code once. code is one of the codes below; fact is the id at the start of the"
                        + " line it cites (F1, B2, S3, R1, P1); MATERIAL_MISSING_EVIDENCE cites the id the UNKNOWN line"
                        + " gives the missing fact (U1).\n");
        block.append("reason: one sentence of at most ").append(MAX_REASON_WORDS)
                .append(" words, in your own words, that names the facts behind your judgment.\n");
        block.append("Reason codes (code: meaning; the lines it cites):\n");
        for (SecurityDecisionOutputContractV4.ReasonCode code : SecurityDecisionOutputContractV4.REASON_CODES) {
            block.append("- ").append(code.code()).append(": ").append(code.meaning()).append("; ")
                    .append(String.join(", ", code.citedFacts().stream()
                            .map(SecurityDecisionOutputContractV5::citedName).distinct().toList()))
                    .append('\n');
        }
        return block.toString();
    }

    /** A cited entry as the output block names it: its line name. */
    private static String citedName(String fact) {
        return fact.substring(fact.indexOf('.') + 1).replace("{i}", "");
    }

    private static String writeProviderSchema(boolean withCodeMeanings) {
        Map<String, Object> factId = new LinkedHashMap<>();
        factId.put("type", "string");
        factId.put("pattern", SecurityDecisionOutputContractV4.FACT_ID_PATTERN);

        Map<String, Object> code = new LinkedHashMap<>();
        code.put("type", "string");
        code.put("enum", SecurityDecisionOutputContractV4.codes());
        if (withCodeMeanings) {
            code.put("description", SecurityDecisionOutputContractV4.REASON_CODES.stream()
                    .map(reason -> reason.code() + ": " + reason.meaning())
                    .collect(Collectors.joining("\n")));
        }
        Map<String, Object> itemProperties = new LinkedHashMap<>();
        itemProperties.put("code", code);
        itemProperties.put("fact", factId);
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("type", "object");
        item.put("additionalProperties", false);
        item.put("required", List.of("code", "fact"));
        item.put("properties", itemProperties);
        Map<String, Object> reasonCodes = new LinkedHashMap<>();
        reasonCodes.put("type", "array");
        reasonCodes.put("minItems", MIN_REASON_CODES);
        reasonCodes.put("maxItems", MAX_REASON_CODES);
        reasonCodes.put("items", item);

        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "string");
        action.put("enum", SecurityDecisionOutputContractV4.ACTIONS);
        Map<String, Object> riskScore = new LinkedHashMap<>();
        riskScore.put("type", "number");
        riskScore.put("minimum", 0);
        riskScore.put("maximum", 1);
        Map<String, Object> hypothesis = new LinkedHashMap<>();
        hypothesis.put("type", "string");
        hypothesis.put("enum", SecurityDecisionOutputContractV4.HYPOTHESES);

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("action", action);
        properties.put("riskScore", riskScore);
        properties.put("hypothesis", hypothesis);
        properties.put("reasonCodes", reasonCodes);
        properties.put("reason", Map.of("type", "string"));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("additionalProperties", false);
        schema.put("required", List.copyOf(properties.keySet()));
        schema.put("properties", properties);
        try {
            return new ObjectMapper().writeValueAsString(schema);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The output contract v5 schema cannot be written", e);
        }
    }
}
