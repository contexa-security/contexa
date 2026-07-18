package io.contexa.contexaiam.admin.promptquality.official.application;

public interface OfficialVerificationPromptFieldStateWriter {

    void insert(Command command);

    void insertMissingActiveDefinitions(String packageId, String aggregateRunId);

    record Command(
            String packageId,
            String aggregateRunId,
            String fieldKey,
            String sourceType,
            String sourceFieldPath,
            String sourceClass,
            String fieldState,
            String valueType,
            String valueHash,
            Integer valueLength,
            String valuePreview,
            String requiredPolicy,
            String applicabilityRule,
            String applicabilityEvidence,
            String projectionPolicy,
            String promptPresenceState,
            String sealedEvidencePresenceState,
            String producerStatus,
            String absenceReasonCode,
            String absenceReasonText,
            String metricImpactPolicy,
            String blockingPolicy,
            Boolean blockingCandidate,
            String qualityRelevance,
            Boolean rawBlockingCandidate,
            Boolean officialBlockingCandidate) {
    }
}
