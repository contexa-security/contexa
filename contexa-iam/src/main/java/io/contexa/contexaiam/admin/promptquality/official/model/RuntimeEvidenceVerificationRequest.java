package io.contexa.contexaiam.admin.promptquality.official.model;

public record RuntimeEvidenceVerificationRequest(
        String packageId,
        String operatorId,
        boolean forceReverification,
        String reverificationReason) {

    public RuntimeEvidenceVerificationRequest(String packageId, String operatorId) {
        this(packageId, operatorId, false, null);
    }
}
