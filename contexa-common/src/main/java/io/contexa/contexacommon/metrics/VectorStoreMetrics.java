package io.contexa.contexacommon.metrics;

import java.util.Map;


public interface VectorStoreMetrics {

    
    void recordOperation(String labName, Object operationType, int documentCount, long durationMs);

    
    void recordError(String labName, Object operationType, Exception error);

    
    void recordEvent(String eventType, Map<String, Object> metadata);

    
    Map<String, Object> getLabStatistics(String labName);
}
