package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class OfficialRunMetricContractView {

    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final FinalPromptMetricContractCatalog finalPromptMetricContracts;

    public OfficialRunMetricContractView(
            PromptQualityOfficialMetricCatalog metricCatalog,
            FinalPromptMetricContractCatalog finalPromptMetricContracts) {
        this.metricCatalog = Objects.requireNonNull(metricCatalog, "metricCatalog");
        this.finalPromptMetricContracts = Objects.requireNonNull(finalPromptMetricContracts, "finalPromptMetricContracts");
    }

    public int expectedMetricCount() {
        return metricCatalog.promptQualityMetrics().size();
    }

    OfficialVerificationMetricDefinition metric(String metricCode) {
        String normalized = normalize(metricCode);
        return metricCatalog.promptQualityMetrics().stream()
                .filter(metric -> normalize(metric.code()).equals(normalized))
                .findFirst()
                .orElse(null);
    }

    String metricPurpose(String metricCode) {
        try {
            FinalPromptMetricContract contract = finalPromptMetricContracts.metric(metricCode);
            return contract.purpose();
        }
        catch (RuntimeException exception) {
            return "";
        }
    }

    String metricQualityQuestion(String metricCode) {
        try {
            FinalPromptMetricContract contract = finalPromptMetricContracts.metric(metricCode);
            return contract.qualityQuestion();
        }
        catch (RuntimeException exception) {
            return "";
        }
    }

    List<OfficialMetricPurposeEvidence> purposeEvidenceForMetric(
            OperatorSnapshot snapshot,
            String metricCode) {
        String normalizedMetric = normalize(metricCode);
        if (snapshot == null || !snapshot.available() || !StringUtils.hasText(normalizedMetric)
                || snapshot.purposeEvidence() == null) {
            return List.of();
        }
        return snapshot.purposeEvidence().stream()
                .filter(evidence -> evidence != null && same(evidence.metricCode(), normalizedMetric))
                .map(this::purposeEvidence)
                .toList();
    }

    private OfficialMetricPurposeEvidence purposeEvidence(OperatorPurposeEvidence evidence) {
        FinalPromptMetricCheckContract contract = metricCheckContract(evidence.metricCode(), evidence.checkCode());
        boolean passed = purposeEvidencePassed(evidence.purposeResult());
        boolean notApplicable = "NOT_APPLICABLE".equals(normalize(evidence.purposeResult()));
        return new OfficialMetricPurposeEvidence(
                valueOrEmpty(evidence.metricCode()),
                valueOrEmpty(evidence.checkCode()),
                valueOrEmpty(evidence.contractVersion()),
                firstNonBlank(contract == null ? null : contract.qualityQuestion(), evidence.signalKey()),
                valueOrEmpty(evidence.promptLocation()),
                firstNonBlank(
                        notApplicable ? contract == null ? null : contract.notApplicableMessage()
                                : passed ? contract == null ? null : contract.passMessage()
                                : contract == null ? null : contract.failureMessage(),
                        evidence.evidenceValue()),
                valueOrEmpty(evidence.evidenceHash()),
                firstNonBlank(contract == null ? null : contract.whyItMatters(), evidence.interpretation()),
                valueOrEmpty(evidence.purposeResult()),
                evidence.customerVisible(),
                valueOrEmpty(evidence.readinessScope()),
                evidence.runtimeFacts(),
                evidence.contextItems());
    }

    FinalPromptMetricCheckContract metricCheckContract(String metricCode, String checkCode) {
        if (!StringUtils.hasText(metricCode) || !StringUtils.hasText(checkCode)) {
            return null;
        }
        try {
            return finalPromptMetricContracts.check(metricCode, checkCode);
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    private boolean purposeEvidencePassed(String purposeResult) {
        String normalized = normalize(purposeResult);
        return "PURPOSE_PASSED".equals(normalized)
                || "PASS".equals(normalized)
                || "SUCCESS".equals(normalized);
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}