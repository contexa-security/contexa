package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;

import java.util.List;
import java.util.Objects;

public final class OfficialVerificationResultAssembler {

    private final OfficialVerificationFailureAssembler failureAssembler;
    private final OfficialVerificationPromptComparisonAssembler promptComparisonAssembler;
    private final OfficialVerificationMetricResultAssembler metricResultAssembler;
    private final OfficialVerificationCustomerNarrativeAssembler customerNarrativeAssembler;

    public OfficialVerificationResultAssembler(
            OfficialVerificationFailureAssembler failureAssembler,
            OfficialVerificationPromptComparisonAssembler promptComparisonAssembler,
            OfficialVerificationMetricResultAssembler metricResultAssembler,
            OfficialVerificationCustomerNarrativeAssembler customerNarrativeAssembler) {
        this.failureAssembler = Objects.requireNonNull(failureAssembler, "failureAssembler");
        this.promptComparisonAssembler = Objects.requireNonNull(
                promptComparisonAssembler, "promptComparisonAssembler");
        this.metricResultAssembler = Objects.requireNonNull(metricResultAssembler, "metricResultAssembler");
        this.customerNarrativeAssembler = Objects.requireNonNull(
                customerNarrativeAssembler, "customerNarrativeAssembler");
    }

    public List<OfficialVerificationPromptComparison> promptComparisons(
            SealedEvidencePackage evidencePackage,
            List<? extends OfficialVerificationRunView> runs) {
        return promptComparisonAssembler.assemble(evidencePackage, runs);
    }

    public List<RuntimeEvidenceMetricResult> metrics(
            List<? extends OfficialVerificationRunView> runs,
            List<OfficialVerificationPromptComparison> promptComparisons,
            String packageId) {
        return metricResultAssembler.assemble(runs, promptComparisons, packageId);
    }

    public List<RuntimeEvidenceMetricResult> issueMetrics(
            List<RuntimeEvidenceMetricResult> metrics,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        return failureAssembler.issueMetrics(metrics, promptConsistency);
    }

    public List<OfficialRunFailureCause> failureCauses(List<RuntimeEvidenceMetricResult> metrics) {
        return failureAssembler.failureCauses(metrics);
    }

    public List<String> customerSentences(List<String> values, boolean blockingFinding) {
        return customerNarrativeAssembler.customerSentences(values, blockingFinding);
    }

    public List<String> findings(
            List<String> verdictFindings,
            List<OfficialActualPromptProblem> problems) {
        return customerNarrativeAssembler.merge(
                customerNarrativeAssembler.customerSentences(verdictFindings, true),
                customerNarrativeAssembler.problemFindings(problems));
    }

    public List<String> nextActions(
            List<String> verdictNextActions,
            List<OfficialActualPromptProblem> problems) {
        return customerNarrativeAssembler.merge(
                customerNarrativeAssembler.customerSentences(verdictNextActions, false),
                customerNarrativeAssembler.problemNextActions(problems));
    }

    public int passedMetricCount(List<RuntimeEvidenceMetricResult> metrics) {
        return customerNarrativeAssembler.passedMetricCount(metrics);
    }

    public int failedMetricCount(List<RuntimeEvidenceMetricResult> metrics) {
        return customerNarrativeAssembler.failedMetricCount(metrics);
    }
}