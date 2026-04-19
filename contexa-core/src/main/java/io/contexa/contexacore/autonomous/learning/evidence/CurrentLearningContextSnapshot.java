package io.contexa.contexacore.autonomous.learning.evidence;

public record CurrentLearningContextSnapshot(
        String accessHour,
        String dayOfWeek,
        String network,
        String browser,
        String operatingSystem,
        String pathFamily,
        String authenticationType,
        String actionFamily,
        String resourceFamily) {
}
