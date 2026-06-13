package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationCcsrExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationCcsrExecutionService.CcsrRunRecord> {

    @Override
    default String metricCode() {
        return "CCSR";
    }
}
