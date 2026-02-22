package io.contexa.contexacore.metrics;

/**
 * Interface for authorization metrics collection.
 * Implemented by enterprise module for detailed metrics recording.
 */
public interface AuthorizationMetrics {

    void recordProtectable(long durationNanos);

    void recordUrlAuth(long durationNanos);

    void recordAuthzDecision();
}
