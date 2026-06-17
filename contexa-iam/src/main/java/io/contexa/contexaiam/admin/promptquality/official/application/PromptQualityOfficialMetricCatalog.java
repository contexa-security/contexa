package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;

import java.util.List;

public interface PromptQualityOfficialMetricCatalog {

    List<OfficialVerificationMetricDefinition> allMetrics();

    default List<OfficialVerificationMetricDefinition> promptQualityMetrics() {
        return allMetrics();
    }
}
