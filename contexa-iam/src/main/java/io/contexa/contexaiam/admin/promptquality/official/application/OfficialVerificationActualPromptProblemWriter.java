package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;

public interface OfficialVerificationActualPromptProblemWriter {

    void insert(String aggregateRunId, String packageId, List<Command> problems);

    record Command(
            String problemId,
            String fieldKey,
            String problemType,
            String promptSection,
            String promptLabel,
            String promptValue,
            String sourceFieldPath,
            String sealedEvidencePath,
            String expectedState,
            String actualState,
            String severity,
            List<String> metricCodes,
            String remediationOwner,
            String qualityQuestion,
            String whyItMatters,
            String fixAction,
            String reverifyCriterion) {
    }
}
