package io.contexa.demo.observation.http.dto;

import java.time.Instant;
import java.util.UUID;

public record BusinessHttpObservation(
        UUID requestId,
        UUID visitorId,
        String method,
        String path,
        Instant startedAt,
        Instant completedAt,
        Integer httpStatus,
        String failureType,
        Long servletOutputBytes,
        String outputCaptureState,
        UUID collectorInstanceId) {
}
