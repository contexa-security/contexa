package io.contexa.contexaiam.admin.web.monitoring.dto;

public record PolicyHealthDto(
        String healthStatus,
        long conflictCount,
        long duplicateCount,
        String combiningAlgorithm) {
}
