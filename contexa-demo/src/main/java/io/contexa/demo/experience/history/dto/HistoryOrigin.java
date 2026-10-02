package io.contexa.demo.experience.history.dto;

public record HistoryOrigin(
        String observationId,
        String requestId,
        String kind,
        String sourceSha256
) {
}
