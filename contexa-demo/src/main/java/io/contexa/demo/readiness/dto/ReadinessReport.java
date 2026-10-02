package io.contexa.demo.readiness.dto;

import java.time.Instant;
import java.util.List;

public record ReadinessReport(
        String role,
        Instant observedAt,
        boolean foundationReady,
        boolean experimentReady,
        boolean modelCallExecuted,
        RuntimeMode runtimeMode,
        List<ReadinessCheckResult> checks,
        List<WorkerReadiness> workers
) {

}
