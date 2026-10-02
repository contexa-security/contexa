package io.contexa.demo.observation.provider.dto;

import io.contexa.demo.observation.model.call.ModelCallReference;

import java.time.Instant;
import java.util.UUID;

public record ProviderHttpObservation(
        UUID id,
        ModelCallReference call,
        String endpoint,
        String method,
        Instant startedAt,
        Instant completedAt,
        Integer httpStatus,
        String failureType,
        ObservedProviderBody requestBody,
        ObservedProviderBody responseBody) {
}
