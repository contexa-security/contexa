package io.contexa.contexacore.std.components.event;

import lombok.Getter;

import java.util.List;


@Getter
public class CleanupResult {
    private final List<String> cleanedSessions;
    private final List<String> failedCleanups;
    private final long cleanupTime;
    private final String status;
    private final String errorMessage;

    public CleanupResult(List<String> cleanedSessions, List<String> failedCleanups, long cleanupTime) {
        this.cleanedSessions = cleanedSessions;
        this.failedCleanups = failedCleanups;
        this.cleanupTime = cleanupTime;
        this.status = "SUCCESS";
        this.errorMessage = null;
    }

    private CleanupResult(String errorMessage) {
        this.cleanedSessions = List.of();
        this.failedCleanups = List.of();
        this.cleanupTime = System.currentTimeMillis();
        this.status = "ERROR";
        this.errorMessage = errorMessage;
    }
    public static CleanupResult error(String errorMessage) {
        return new CleanupResult(errorMessage);
    }
}