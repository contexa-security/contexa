package io.contexa.contexaiam.admin.promptquality.official.model;

public record OfficialInspectionCheckResponse(
        String checkCode,
        String label,
        boolean passed,
        String expectedValue,
        String actualValue,
        String severity,
        String failureType,
        String source
) {
}
