package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialRunEventDetail(
        int sequence,
        String type,
        String layer,
        String status,
        String requestPath) {
}
