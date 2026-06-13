package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationBsrExecutor extends OfficialVerificationLongHorizonMetricExecutor<OfficialVerificationBsrExecutionService.BsrRunRecord> {

    @Override
    default String metricCode() {
        return "BSR";
    }
}
