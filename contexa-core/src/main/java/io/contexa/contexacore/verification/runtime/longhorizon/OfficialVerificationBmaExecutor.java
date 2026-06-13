package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationBmaExecutor extends OfficialVerificationLongHorizonMetricExecutor<OfficialVerificationBmaExecutionService.BmaRunRecord> {

    @Override
    default String metricCode() {
        return "BMA";
    }
}
