package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;

public interface OfficialVerificationPromptComparisonWriter {

    void insert(PromptComparisonCommand command);

    record PromptComparisonCommand(
            String aggregateRunId,
            String packageId,
            OfficialVerificationPromptComparison comparison,
            String sealedEvidenceDisplay,
            String promptDisplay,
            String officialFactDisplay) {
    }
}
