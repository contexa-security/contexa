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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-4 (plan 5.4, the rule test over the case facts): the minimum action rules on the facts the real server decided each
 * golden case on (the sealed canonical context of the P3 gate measurement), against a table computed apart from the
 * code from dictionary 6. R1 has no golden input (no model call). No golden export has an unexplained device or
 * network, so P2 is met by none; the unit test covers it.
 */
class MinimumActionRulesGoldenCasesTest {

    /** Case to rule hits, "P1:DEVICE+TIME" naming the unexplained identity dimensions (repro w44_rule_table.py). */
    private static final Map<String, List<String>> EXPECTED = Map.ofEntries(
            Map.entry("A1", List.of("P1:DEVICE+NETWORK")),
            Map.entry("A1T", List.of()),
            Map.entry("A3", List.of("P3")),
            Map.entry("A3S", List.of("P3")),
            Map.entry("A3ST", List.of()),
            Map.entry("A3T", List.of()),
            Map.entry("A5", List.of("P3")),
            Map.entry("A5T", List.of()),
            Map.entry("A6", List.of("P3")),
            Map.entry("A6T", List.of()),
            Map.entry("A8", List.of("P3")),
            Map.entry("A8T", List.of()),
            Map.entry("K2", List.of("P1:DEVICE+TIME")),
            Map.entry("S01", List.of()),
            Map.entry("S02", List.of()),
            Map.entry("S03", List.of()),
            Map.entry("S04", List.of("P1:DEVICE+TIME", "P3")),
            Map.entry("S05", List.of("P3")),
            Map.entry("S06", List.of("P3")),
            Map.entry("S07", List.of("P3")),
            Map.entry("S08", List.of()),
            Map.entry("S09", List.of("P3")),
            Map.entry("S09C", List.of("P3")),
            Map.entry("S10", List.of("P1:DEVICE+TIME")),
            Map.entry("S11", List.of()),
            Map.entry("S12", List.of("P3")));

    @Test
    void everyGoldenCaseMeetsTheRulesDictionarySixGivesItsFacts() {
        CanonicalSecurityContextSerializer serializer =
                new CanonicalSecurityContextSerializer(new ObjectMapper().findAndRegisterModules());
        Map<String, List<String>> actual = new TreeMap<>();
        for (JsonNode goldenCase : SecurityDecisionGoldenRender.load().cases()) {
            CanonicalSecurityContext canonical = serializer.deserialize(goldenCase.path("canonicalContext").toString());
            CanonicalSecurityContext.Resource resource = canonical.getResource();
            actual.put(goldenCase.path("caseKey").asText(), MinimumActionRules.evaluate(canonical.getDecisionFacts(),
                            resource.getResourceClass(), resource.getActionFamily(), MinimumActionRules.Settings.DEFAULTS)
                    .stream().map(MinimumActionRulesGoldenCasesTest::label).toList());
        }

        assertThat(actual).isEqualTo(new TreeMap<>(EXPECTED));
    }

    private static String label(MinimumActionRules.Hit hit) {
        String rule = hit.rule().name().substring(0, 2);
        String dimensions = hit.dimensions().stream().map(Enum::name).sorted().collect(Collectors.joining("+"));
        return dimensions.isEmpty() ? rule : rule + ":" + dimensions;
    }
}
