package io.contexa.demo.observation.provider.dto;

public record ObservedProviderBody(
        String state,
        long observedBytes,
        boolean complete,
        String observedBytesSha256,
        String sanitizedJson,
        String completionBasis) {
}
