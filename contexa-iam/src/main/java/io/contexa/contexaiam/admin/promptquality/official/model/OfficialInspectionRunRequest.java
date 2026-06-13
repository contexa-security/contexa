package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialInspectionRunRequest(
        String packageId,
        String operatorId
) {
}
