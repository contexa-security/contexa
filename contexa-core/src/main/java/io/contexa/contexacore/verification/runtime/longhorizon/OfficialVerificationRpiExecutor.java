package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationRpiExecutor extends OfficialVerificationLongHorizonMetricExecutor<OfficialVerificationRpiExecutionService.RpiRunRecord> {

    @Override
    default String metricCode() {
        return "RPI";
    }
}
