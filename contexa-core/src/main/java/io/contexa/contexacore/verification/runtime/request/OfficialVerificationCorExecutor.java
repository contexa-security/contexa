package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationCorExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationCorExecutionService.CorRunRecord> {

    @Override
    default String metricCode() {
        return "CoR";
    }
}
