package io.contexa.contexacore.std.llm.bulkhead;

public record OllamaBulkheadSettings(
        int maxConcurrent,
        long acquireTimeoutMs,
        int retryAttempts,
        long retryDelayMs,
        int busyTripThreshold,
        long circuitOpenMs
) {

    public OllamaBulkheadSettings {
        maxConcurrent = Math.max(1, maxConcurrent);
        acquireTimeoutMs = Math.max(1L, acquireTimeoutMs);
        retryAttempts = Math.max(0, retryAttempts);
        retryDelayMs = Math.max(0L, retryDelayMs);
        busyTripThreshold = Math.max(1, busyTripThreshold);
        circuitOpenMs = Math.max(0L, circuitOpenMs);
    }
}
