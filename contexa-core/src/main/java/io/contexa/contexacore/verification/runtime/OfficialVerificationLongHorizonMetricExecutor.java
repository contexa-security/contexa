package io.contexa.contexacore.verification.runtime;


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
            OfficialVerificationExecutionRequest request,
            String runId,
            int runOrdinal
    );
}