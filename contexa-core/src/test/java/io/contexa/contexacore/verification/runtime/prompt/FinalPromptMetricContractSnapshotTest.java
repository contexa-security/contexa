package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FinalPromptMetricContractSnapshotTest {

    private static final List<String> OFFICIAL_METRIC_CODES = List.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR",
            "RAP", "RPI", "BMA", "USNS", "BSR", "PRE"
    );

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
            for (JsonNode contract : contracts) {
                String metricCode = contract.path("metricCode").asText();
                assertThat(contract.path("version").asText()).isEqualTo("final-user-prompt.v1");
                assertThat(contract.path("checks").isArray()).isTrue();
                assertThat(contract.path("checks")).isNotEmpty();
                for (JsonNode check : contract.path("checks")) {
                    assertThat(check.path("metricCode").asText()).isEqualTo(metricCode);
                    assertThat(check.path("checkName").asText()).isNotBlank();
                    assertThat(checkCodes.add(metricCode + ":" + check.path("checkName").asText()))
                            .as("duplicate metric/check contract")
                            .isTrue();
                }
            }
        }
    }
}
