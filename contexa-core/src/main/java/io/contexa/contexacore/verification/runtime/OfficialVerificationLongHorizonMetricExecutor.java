package io.contexa.contexacore.verification.runtime;

import jakarta.servlet.http.HttpServletRequest;

public interface OfficialVerificationLongHorizonMetricExecutor<R extends OfficialVerificationRunView> extends OfficialVerificationRequestMetricExecutor<R> {

    R executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request,
            String runId,
            int runOrdinal
    );
}