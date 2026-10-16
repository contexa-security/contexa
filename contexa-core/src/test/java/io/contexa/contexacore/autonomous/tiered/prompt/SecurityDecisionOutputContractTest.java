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
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The output contract v3 (W4-2, dictionary 4 and 5): the reason codes and the schema a provider with structured output
 * enforces.
 */
class SecurityDecisionOutputContractTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * W4-8 (5): a code the resolver puts on a decision fact is a reason code of the contract: the deviation and policy
     * reason codes by their enums, the others where the resolver writes them (a list, an added code, a chosen code).
     */
    @Test
    void everyCodeTheResolverPutsOnAFactIsAReasonCode() throws IOException {
        Set<String> contract = Set.copyOf(SecurityDecisionOutputContract.codes());
        for (DeviationDimension dimension : DeviationDimension.values()) {
            assertThat(contract).as(dimension.name()).contains(dimension.code());
        }
        for (PolicyReason reason : PolicyReason.values()) {
            assertThat(contract).as(reason.name()).contains(reason.code());
        }
        String resolver = Files.readString(Path.of(
                "src/main/java/io/contexa/contexacore/autonomous/context/decision/DecisionFactsResolver.java"));
        Matcher written = Pattern.compile("(?:List\\.of\\(|codes\\.add\\(|\\? |: )\"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\"")
                .matcher(resolver);
        Set<String> codes = new TreeSet<>();
        while (written.find()) {
            codes.add(written.group(1));
        }
        assertThat(codes).contains("APPROVAL_COVERS", "TENANT_CONFLICT", "DATA_CONFLICT", "DEVIATION_MOVEMENT");
        assertThat(codes).allSatisfy(code -> assertThat(contract).as(code).contains(code));
    }

    /** N-FRIC-1 (Q-87): a repeat in the session is a fact; alone it asks for no stronger action. */
    @Test
    void aRepeatAloneIsNoReasonForAStrongerAction() {
        assertThat(SecurityDecisionOutputContract.REASON_CODES)
                .filteredOn(code -> "REPEAT_IN_SESSION".equals(code.code()))
                .singleElement()
                .extracting(SecurityDecisionOutputContract.ReasonCode::meaning)
                .isEqualTo("the same action repeats in the session (a repeat alone is no reason for a stronger action)");
    }

    /** N-UID-1 (Q-87): the missing-evidence code cites the ID the UNKNOWN line gives the missing fact. */
    @Test
    void theMissingEvidenceCodeCitesTheIdOfTheMissingFact() {
        assertThat(SecurityDecisionOutputContract.systemOutputBlock())
                .contains("MATERIAL_MISSING_EVIDENCE cites the ID the UNKNOWN line gives the missing fact (U1).")
                .doesNotContain("the first ID of the block");
    }

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
        assertThat(item.path("properties").path("fact").path("pattern").asText()).isEqualTo("^[BSRFPU][0-9]{1,2}$");
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

    /**
     * W4-2 (dictionary 5): with structured output the code enum carries the meaning of every code, the same words as
     * the output block; the schema text a provider without structured output gets in the system prompt does not repeat
     * them (dictionary 4: the same schema, and the output block already states the meanings).
     */
    @Test
    void theCodeEnumCarriesTheMeaningsAndTheSchemaTextDoesNotRepeatThem() throws Exception {
        JsonNode code = MAPPER.readTree(SecurityDecisionOutputContract.providerSchema())
                .path("properties").path("reasonCodes").path("items").path("properties").path("code");
        String description = code.path("description").asText();
        for (SecurityDecisionOutputContract.ReasonCode reason : SecurityDecisionOutputContract.REASON_CODES) {
            assertThat(description).as(reason.code()).contains(reason.code() + ": " + reason.meaning());
        }
        assertThat(SecurityDecisionOutputContract.textSchema()).doesNotContain("\"description\"");
        assertThat(SecurityDecisionContractSectionBuilder.formatInstructions(true))
                .contains(SecurityDecisionOutputContract.textSchema()).doesNotContain("\"description\"");
        JsonNode text = MAPPER.readTree(SecurityDecisionOutputContract.textSchema());
        assertThat(texts(text.path("properties").path("reasonCodes").path("items").path("properties").path("code")
                .path("enum"))).containsExactlyElementsOf(SecurityDecisionOutputContract.codes());
    }

    /**
     * W4-2: the schema is written in one key order whatever the JVM (type before enum), so the provider schema and the
     * system text of a provider without structured output are the same text on every run.
     */
    @Test
    void theSchemaIsWrittenInOneKeyOrder() {
        String action = "\"action\":{\"type\":\"string\",\"enum\":[\"ALLOW\",\"CHALLENGE\",\"ESCALATE\",\"BLOCK\"]}";
        assertThat(SecurityDecisionOutputContract.providerSchema()).contains(action);
        assertThat(SecurityDecisionOutputContract.textSchema()).contains(action);
    }

    /** W4-2: the output block names every code once, in the dictionary's group order, with the line it cites. */
    @Test
    void theOutputBlockNamesEveryCodeOnce() {
        String block = SecurityDecisionOutputContract.systemOutputBlock();

        assertThat(block).startsWith("=== OUTPUT ===");
        int last = -1;
        for (SecurityDecisionOutputContract.ReasonCode code : SecurityDecisionOutputContract.REASON_CODES) {
            String line = "- " + code.code() + ": " + code.meaning() + "; ";
            assertThat(block.indexOf(line)).as(code.code()).isGreaterThan(last);
            assertThat(block.indexOf(line)).isEqualTo(block.lastIndexOf(line));
            last = block.indexOf(line);
        }
        assertThat(block).contains("- MIN_P3_POLICY_NOT_SATISFIED: no valid record covers what the company policy requires;"
                + " PolicySatisfied");
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return values;
    }
}
