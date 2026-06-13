package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationUsnsExecutor extends OfficialVerificationLongHorizonMetricExecutor<OfficialVerificationUsnsExecutionService.UsnsRunRecord> {

    @Override
    default String metricCode() {
        return "USNS";
    }
}
