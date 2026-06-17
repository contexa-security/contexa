package io.contexa.contexaiam.admin.promptquality.official.application;

public record ProtectableResourceDescriptor(
        String beanName,
        String methodIdentifier,
        String resourceId,
        String resourceUrl,
        String httpMethod,
        String criticality,
        boolean verificationRequired,
        boolean sync,
        String ownerField,
        String sourceClassName,
        String sourceMethodName,
        String annotationSignatureHash,
        String certificateState,
        String operationalState,
        String latestCertificateId,
        boolean signatureChanged) {

    public ProtectableResourceDescriptor(
            String beanName,
            String methodIdentifier,
            String resourceId,
            String resourceUrl,
            String httpMethod,
            String criticality,
            boolean verificationRequired,
            boolean sync,
            String ownerField) {
        this(
                beanName,
                methodIdentifier,
                resourceId,
                resourceUrl,
                httpMethod,
                criticality,
                verificationRequired,
                sync,
                ownerField,
                null,
                null,
                null,
                "REVIEW_REQUIRED",
                "PENDING_VERIFICATION",
                null,
                false);
    }
}
