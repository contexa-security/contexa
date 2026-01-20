package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;


public interface EventRecorder {

    
    void recordEvent(String eventType, Map<String, Object> metadata);

    
    void recordDuration(String operationName, long durationNanos);
}
