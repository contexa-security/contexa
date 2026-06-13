package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationMtrExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationMtrExecutionService.MtrRunRecord> {

    @Override
    default String metricCode() {
        return "MTR";
    }
}
