package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.List;

public interface PromptQualityRuntimeCertificateIssuer {

    PromptQualityCertificateService.PromptQualityCertificate issue(
            String generatedAt,
            String operatorId,
            PromptQualityCertificateService.CertificateScope scope,
            ProtectableResourceDescriptor descriptor,
            List<PromptQualityCertificateService.MetricRunEvidence> evidence,
            List<PromptQualityCertificateService.MetricExecutionFailure> failures);
}
