package io.contexa.contexacore.autonomous.learning.evidence;

public record RetrievedBehaviorEvidence(
        LearningEvidenceScope scope,
        String sourceUserId,
        String documentType,
        String artifactId,
        Double similarityScore,
        String sourceIp,
        String ipBand,
        String requestPath,
        String pathFamily,
        String accessHour,
        String accessDay,
        String browser,
        String operatingSystem,
        String authenticationType,
        String actionFamily,
        String resourceFamily,
        String resourceSensitivity,
        String businessLabel,
        String sessionAgeMinutes,
        String intentBotUserAgent,
        String summary) {
}
