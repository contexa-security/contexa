package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationPfrExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationPfrExecutionService.PfrRunRecord> {

    @Override
    default String metricCode() {
        return "PFR";
    }
}
