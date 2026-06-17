package io.contexa.contexaiam.admin.promptquality.official.domain;

public record PromptQualityAssuranceStage(
        String stageId,
        String caseId,
        String stage,
        String sourceRef,
        String summary,
        String recordedAt) {
}
