package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;

import java.util.List;

public interface OfficialVerificationPromptComparisonRepository {
    List<OfficialVerificationPromptComparison> findByPackageAndAggregateRunId(String packageId, String aggregateRunId);
}