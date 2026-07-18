package io.contexa.contexacore.verification.runtime;


import java.util.List;

public interface OfficialVerificationRequestMetricExecutor<R extends OfficialVerificationRunView> extends OfficialVerificationMetricExecutor<R> {

    R executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    );

    List<? extends R> listRuns(String userId);

    R findRun(String userId, String runId);
}