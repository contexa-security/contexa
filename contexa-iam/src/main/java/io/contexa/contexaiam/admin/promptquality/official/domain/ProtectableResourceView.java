package io.contexa.contexaiam.admin.promptquality.official.domain;

import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDescriptor;

public record ProtectableResourceView(
        String resourceId,
        String resourceUrl,
        String httpMethod,
        String criticality,
        boolean verificationRequired,
        boolean sync,
        String ownerField,
        String sourceClassName,
        String sourceMethodName,
        String certificateState,
        String certificateStateLabel,
        String operationalState,
        String operationalStateLabel,
        String latestCertificateId,
        boolean signatureChanged,
        String plainStatus,
        String nextAction,
        String tenantId,
        String promptContractVersion,
        String modelProfile,
        String verifierVersion,
        PromptQualityStateDescriptor runtimeRequestStateDescriptor) {
}
