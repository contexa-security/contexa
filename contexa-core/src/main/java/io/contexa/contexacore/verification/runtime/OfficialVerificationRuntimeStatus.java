package io.contexa.contexacore.verification.runtime;

import java.util.List;

public record OfficialVerificationRuntimeStatus(
        boolean officialExecutionReady,
        int supportedMetricCount,
        List<String> supportedMetricCodes,
        String message) {
}
