package io.contexa.demo.readiness.dto;

import java.time.Instant;

public record WorkerReadiness(
        String role,
        Instant checkedAt,
        String state,
        Integer httpStatus,
        ReadinessReport report
) {

}
