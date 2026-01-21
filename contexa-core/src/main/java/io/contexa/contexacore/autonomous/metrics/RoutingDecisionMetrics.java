package io.contexa.contexacore.autonomous.metrics;

import java.util.Map;

public interface RoutingDecisionMetrics {

    void recordHotPath(long durationNanos, String processingMode);

    void recordColdPath(long durationNanos, String processingMode);

    void recordEvent(String eventType, Map<String, Object> metadata);
}
