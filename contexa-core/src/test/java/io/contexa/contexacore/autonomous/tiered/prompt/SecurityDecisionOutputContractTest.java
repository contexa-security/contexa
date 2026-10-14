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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The output contract v3 (W4-2, dictionary 4 and 5): the reason codes and the schema a provider with structured output
 * enforces.
 */
class SecurityDecisionOutputContractTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @DisplayName("the reason codes are the dictionary's 53, by group, each once")
    void theReasonCodesAreTheDictionarys() {
        List<SecurityDecisionOutputContract.ReasonCode> codes = SecurityDecisionOutputContract.REASON_CODES;

        // Dictionary 5 after R4-T took TRUSTED_SIGNAL_MALICIOUS out with its fact: 53 codes.
        assertThat(codes).hasSize(53);
        assertThat(codes.stream().map(SecurityDecisionOutputContract.ReasonCode::code).distinct()).hasSize(53);
        Map<SecurityDecisionOutputContract.Group, Long> byGroup = codes.stream().collect(Collectors.groupingBy(
                SecurityDecisionOutputContract.ReasonCode::group, LinkedHashMap::new, Collectors.counting()));
        assertThat(byGroup).containsExactly(
                Map.entry(SecurityDecisionOutputContract.Group.MINIMUM_ACTION, 3L),
                Map.entry(SecurityDecisionOutputContract.Group.POLICY, 9L),
                Map.entry(SecurityDecisionOutputContract.Group.BUSINESS_RECORDS, 7L),
                Map.entry(SecurityDecisionOutputContract.Group.DEVIATION, 13L),
                Map.entry(SecurityDecisionOutputContract.Group.AS_USUAL, 2L),
                Map.entry(SecurityDecisionOutputContract.Group.SCOPE_AND_PERMISSIONS, 3L),
                Map.entry(SecurityDecisionOutputContract.Group.DELEGATION, 1L),
                Map.entry(SecurityDecisionOutputContract.Group.SESSION, 5L),
                Map.entry(SecurityDecisionOutputContract.Group.PAST_RECORDS, 3L),
                Map.entry(SecurityDecisionOutputContract.Group.BLOCK_GROUNDS, 5L),
                Map.entry(SecurityDecisionOutputContract.Group.ESCALATION, 2L));
        assertThat(codes).allSatisfy(code -> {
            assertThat(code.code()).matches("[A-Z][A-Z0-9_]+");
            assertThat(code.meaning()).isNotBlank();
            assertThat(code.citedFacts()).isNotEmpty();
        });
        assertThat(SecurityDecisionOutputContract.codes())
                .contains("MIN_P3_POLICY_NOT_SATISFIED", "DEVIATION_MOVEMENT", "MATERIAL_MISSING_EVIDENCE")
                .doesNotContain("TRUSTED_SIGNAL_MALICIOUS", "APPROVAL_VALID");
    }

    @Test
    @DisplayName("every fact a reason code cites is an entry of the dictionary")
    void everyCitedFactIsADictionaryEntry() {
        Set<String> entries = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .map(entry -> entry.block().name() + "." + entry.name())
                .collect(Collectors.toSet());
        List<String> missing = new ArrayList<>();
        for (SecurityDecisionOutputContract.ReasonCode code : SecurityDecisionOutputContract.REASON_CODES) {
            for (String fact : code.citedFacts()) {
                if (!entries.contains(fact)) {
                    missing.add(code.code() + " -> " + fact);
                }
            }
        }

        assertThat(missing).isEmpty();
    }

    @Test
    @DisplayName("the provider schema is strict: every field required, no extra keys, audit fields nullable")
    void theProviderSchemaIsStrict() throws Exception {
        JsonNode schema = MAPPER.readTree(SecurityDecisionOutputContract.providerSchema());

        assertThat(schema.path("type").asText()).isEqualTo("object");
        assertThat(schema.path("additionalProperties").asBoolean(true)).isFalse();
        assertThat(texts(schema.path("required")))
                .containsExactly("action", "reasonCodes", "reason", "riskScore", "confidence", "mitre");
        JsonNode properties = schema.path("properties");
        assertThat(texts(properties.path("action").path("enum")))
                .containsExactly("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
        JsonNode reasonCodes = properties.path("reasonCodes");
        assertThat(reasonCodes.path("type").asText()).isEqualTo("array");
        assertThat(reasonCodes.path("minItems").asInt()).isEqualTo(1);
        assertThat(reasonCodes.path("maxItems").asInt()).isEqualTo(5);
        JsonNode item = reasonCodes.path("items");
        assertThat(item.path("additionalProperties").asBoolean(true)).isFalse();
        assertThat(texts(item.path("required"))).containsExactly("code", "fact");
        assertThat(texts(item.path("properties").path("code").path("enum")))
                .containsExactlyElementsOf(SecurityDecisionOutputContract.codes());
        assertThat(item.path("properties").path("fact").path("pattern").asText()).isEqualTo("^[BSRFP][0-9]{1,2}$");
        assertThat(properties.path("reason").path("type").asText()).isEqualTo("string");
        for (String audit : List.of("riskScore", "confidence")) {
            assertThat(texts(properties.path(audit).path("type"))).containsExactly("number", "null");
            assertThat(properties.path(audit).path("minimum").asInt()).isZero();
            assertThat(properties.path(audit).path("maximum").asInt()).isEqualTo(1);
        }
        assertThat(texts(properties.path("mitre").path("type"))).containsExactly("array", "null");
    }

    @Test
    @DisplayName("the provider schema uses only keywords strict structured output supports (P4-CHANGE-2)")
    void theProviderSchemaUsesOnlySupportedKeywords() {
        String schema = SecurityDecisionOutputContract.providerSchema();

        // OpenAI strict structured output lists no string length keyword; the response processor keeps the length.
        assertThat(schema).doesNotContain("maxLength", "minLength", "$schema", "allOf", "\"not\"", "\"if\"");
        assertThat(SecurityDecisionOutputContract.MAX_REASON_CHARACTERS).isEqualTo(200);
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return values;
    }
}
