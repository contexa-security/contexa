package io.contexa.contexacore.autonomous.execution;

public record ObjectiveDescriptor(
        String taskIntent,
        String taskPurpose,
        String objectiveId,
        String objectiveFamily,
        String objectiveSummary) {

    public boolean objectiveBound() {
        return objectiveFamily != null && !objectiveFamily.isBlank();
    }
}