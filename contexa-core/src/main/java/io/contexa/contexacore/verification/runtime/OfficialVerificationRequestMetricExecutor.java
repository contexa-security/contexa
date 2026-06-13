package io.contexa.contexacore.verification.runtime;

import jakarta.servlet.http.HttpServletRequest;

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
            HttpServletRequest request
    );

    List<? extends R> listRuns(String userId);

    R findRun(String userId, String runId);
}