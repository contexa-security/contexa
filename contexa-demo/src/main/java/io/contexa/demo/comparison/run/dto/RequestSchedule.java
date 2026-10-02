package io.contexa.demo.comparison.run.dto;

import java.time.Duration;

public record RequestSchedule(
        int requestsPerArm,
        int maximumConcurrentRequests,
        Duration interval,
        Duration requestTimeout,
        Duration dispatchWindow,
        String stopCondition,
        boolean automaticBusinessRetry
) {
}
