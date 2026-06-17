package io.contexa.contexaiam.admin.promptquality.official.domain;

public record PromptQualityDependencyImpact(
        String impactId,
        String caseId,
        String sourceType,
        String sourceRef,
        String impactState,
        String reasonCode,
        String summary,
        String recordedAt) {
}
