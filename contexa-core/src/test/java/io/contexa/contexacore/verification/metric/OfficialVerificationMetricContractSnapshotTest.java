package io.contexa.contexacore.verification.metric;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationMetricContractSnapshotTest {

    @Test
    void twelvePromptMetricDefinitionsAndExecutableContractsStayAligned() {
        OfficialVerificationMetricCatalog metricCatalog = new OfficialVerificationMetricCatalog();

        assertThat(metricCatalog.promptQualityMetrics())
                .extracting(this::snapshot)
                .containsExactly(
                        "EIR|Event Integrity Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "CCR|Context Completeness Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "CCSR|Context Consistency Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "PFR|Prompt Fidelity Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "MTR|Metadata Traceability Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "COR|Context Contamination Rate|IMPLEMENTATION_ALIGNMENT|true|95.0|true",
                        "RAP|RAG Authorization Precision|RAG_AND_BASELINE|true|95.0|true",
                        "RPI|Round Progression Integrity|RAG_AND_BASELINE|true|95.0|true",
                        "BMA|Baseline Maturity Accuracy|RAG_AND_BASELINE|true|95.0|true",
                        "USNS|User-Specific Novelty Sensitivity|BEHAVIORAL_CONTEXT|true|95.0|true",
                        "BSR|Behavioral Surprise Resolution|BEHAVIORAL_CONTEXT|true|95.0|true",
                        "PRE|Protectable Resource Eligibility|RESOURCE_ELIGIBILITY|true|100.0|true");

        FinalPromptMetricContractCatalog executableContracts =
                FinalPromptMetricContractCatalog.load(new ObjectMapper());
        assertThat(executableContracts.metricCodesInOrder())
                .containsExactly("EIR", "CCR", "CCSR", "PFR", "MTR", "COR",
                        "RAP", "RPI", "BMA", "USNS", "BSR", "PRE");
        assertThat(executableContracts.contractVersion()).isNotBlank();
    }

    private String snapshot(OfficialVerificationMetricDefinition metric) {
        return metric.code()
                + "|" + metric.metricName()
                + "|" + metric.category()
                + "|" + metric.higherIsBetter()
                + "|" + metric.benchmarkSuccessThreshold()
                + "|" + metric.official();
    }
}