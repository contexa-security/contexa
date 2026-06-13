package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationRapExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationRapExecutionService.RapRunRecord> {

    @Override
    default String metricCode() {
        return "RAP";
    }
}
