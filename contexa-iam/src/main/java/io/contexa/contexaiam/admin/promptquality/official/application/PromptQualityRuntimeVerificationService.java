package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;

public interface PromptQualityRuntimeVerificationService {

    RuntimeEvidenceVerificationRun verify(RuntimeEvidenceVerificationRequest request);

    RuntimeEvidenceReverifyResult reverify(RuntimeEvidenceReverifyRequest request);

    default OfficialVerificationExecutionStatus executionStatus(String packageId) {
        return OfficialVerificationExecutionStatus.empty(packageId);
    }

    default OfficialVerificationExecutionStatus executionStatus(String packageId, String aggregateRunId) {
        return executionStatus(packageId);
    }
}
