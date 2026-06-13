package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.*;

public interface OfficialVerificationEirExecutor extends OfficialVerificationRequestMetricExecutor<OfficialVerificationEirExecutionService.EirRunRecord> {

    @Override
    default String metricCode() {
        return "EIR";
    }
}
