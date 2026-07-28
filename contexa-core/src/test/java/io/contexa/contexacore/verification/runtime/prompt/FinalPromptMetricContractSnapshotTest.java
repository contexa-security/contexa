package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.metric.OfficialVerificationDefinitionCatalog;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FinalPromptMetricContractSnapshotTest {

    private static final List<String> OFFICIAL_METRIC_CODES = List.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR",
            "RAP", "RPI", "BMA", "USNS", "BSR", "PRE"
    );

    private static final Map<String, Integer> OFFICIAL_CHECK_COUNTS = Map.ofEntries(
            Map.entry("EIR", 5), Map.entry("CCR", 5), Map.entry("CCSR", 15),
            Map.entry("PFR", 5), Map.entry("MTR", 5), Map.entry("COR", 7),
            Map.entry("RAP", 6), Map.entry("RPI", 4), Map.entry("BMA", 3),
            Map.entry("USNS", 3), Map.entry("BSR", 4), Map.entry("PRE", 4));

    private static final Map<String, String> OFFICIAL_METRIC_ROLES = Map.ofEntries(
            Map.entry("EIR", "ATTACK_DETECTION"), Map.entry("CCR", "ATTACK_DETECTION"),
            Map.entry("CCSR", "ATTACK_DETECTION"), Map.entry("PFR", "PROMPT_FIDELITY"),
            Map.entry("MTR", "INTERNAL_GATE"), Map.entry("COR", "CONDITIONAL_RAG"),
            Map.entry("RAP", "CONDITIONAL_RAG"), Map.entry("RPI", "INTERNAL_GATE"),
            Map.entry("BMA", "ATTACK_DETECTION"), Map.entry("USNS", "ATTACK_DETECTION"),
            Map.entry("BSR", "ATTACK_DETECTION"), Map.entry("PRE", "INTERNAL_GATE"));

    @Test
    void ossOwnsTheCanonicalTwelveMetricContractSnapshot() throws Exception {
        try (InputStream input = getClass().getResourceAsStream(
                "/pqa/final-prompt-metric-contracts.json")) {
            assertThat(input).as("canonical prompt metric contract resource").isNotNull();
            JsonNode contracts = new ObjectMapper().readTree(input);

            assertThat(contracts.isArray()).isTrue();
            assertThat(contracts).hasSize(12);
            assertThat(contracts).extracting(node -> node.path("metricCode").asText())
                    .containsExactlyElementsOf(OFFICIAL_METRIC_CODES);

            Set<String> checkCodes = new LinkedHashSet<>();
            int totalCheckCount = 0;
            for (JsonNode contract : contracts) {
                String metricCode = contract.path("metricCode").asText();
                assertThat(contract.path("version").asText()).isEqualTo("final-user-prompt.v1");
                assertThat(contract.path("checks").isArray()).isTrue();
                assertThat(contract.path("checks"))
                        .hasSize(OFFICIAL_CHECK_COUNTS.get(metricCode));
                assertThat(contract.path("metricRole").asText())
                        .isEqualTo(OFFICIAL_METRIC_ROLES.get(metricCode));
                assertThat(contract.path("blocksLlmSubmission").asBoolean())
                        .isEqualTo(!Set.of("RPI", "PRE").contains(metricCode));
                assertThat(contract.path("blocksCertificate").asBoolean()).isTrue();
                totalCheckCount += contract.path("checks").size();
                for (JsonNode check : contract.path("checks")) {
                    assertThat(check.path("metricCode").asText()).isEqualTo(metricCode);
                    assertThat(check.path("checkName").asText()).isNotBlank();
                    assertThat(checkCodes.add(metricCode + ":" + check.path("checkName").asText()))
                            .as("duplicate metric/check contract")
                            .isTrue();
                }
            }
            assertThat(totalCheckCount).isEqualTo(66);
            assertThat(checkCodes).hasSize(66);
        }
    }

    @Test
    void persistenceDefinitionsAreDerivedFromTheCanonicalContract() {
        FinalPromptMetricContractCatalog catalog = FinalPromptMetricContractCatalog.load(new ObjectMapper());
        Set<String> canonicalChecks = new LinkedHashSet<>();
        catalog.metrics().forEach(metric -> metric.checks().forEach(check ->
                canonicalChecks.add(metric.metricCode() + ":" + check.checkName())));

        assertThat(OfficialVerificationDefinitionCatalog.VERSION)
                .isEqualTo(catalog.contractVersion());
        assertThat(OfficialVerificationDefinitionCatalog.metrics())
                .extracting(OfficialVerificationDefinitionCatalog.MetricSeed::code)
                .containsExactlyElementsOf(catalog.metricCodesInOrder());
        assertThat(OfficialVerificationDefinitionCatalog.checks())
                .extracting(check -> check.metricCode() + ":" + check.checkCode())
                .containsExactlyElementsOf(canonicalChecks);
    }
}
