package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;

import java.util.List;

public class DefaultPromptQualityOfficialMetricCatalog implements PromptQualityOfficialMetricCatalog {

    private final OfficialVerificationMetricCatalog metricCatalog;

    public DefaultPromptQualityOfficialMetricCatalog(OfficialVerificationMetricCatalog metricCatalog) {
        this.metricCatalog = metricCatalog;
    }

    @Override
    public List<OfficialVerificationMetricDefinition> allMetrics() {
        return metricCatalog.promptQualityMetrics();
    }
}
