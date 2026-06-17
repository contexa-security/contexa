package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;

import java.util.List;

public interface RuntimeIssueDiagnosticService {

    default List<PromptQualityIssue> recordIssues(
            String runId,
            String packageId,
            List<RuntimeEvidenceMetricResult> metrics,
            List<String> nextActions) {
        return recordIssues(runId, packageId, null, metrics, nextActions);
    }

    List<PromptQualityIssue> recordIssues(
            String runId,
            String packageId,
            String httpMethod,
            List<RuntimeEvidenceMetricResult> metrics,
            List<String> nextActions);
}
