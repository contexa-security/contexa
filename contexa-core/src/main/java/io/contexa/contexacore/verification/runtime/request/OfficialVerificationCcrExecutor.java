package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationCcrExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationCcrExecutionService.CcrRunRecord> {

    @Override
    default String metricCode() {
        return "CCR";
    }
}
