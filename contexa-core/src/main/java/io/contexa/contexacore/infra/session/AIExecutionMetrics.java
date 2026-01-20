package io.contexa.contexacore.infra.session;

import java.util.HashMap;
import java.util.Map;


public class AIExecutionMetrics {
    private final String sessionId;
    private final long startTime;
    private final long endTime;
    private final long processingTime;
    private final int requestCount;
    private final int successCount;
    private final int errorCount;
    private final Map<String, Object> customMetrics;
    
    public AIExecutionMetrics(String sessionId, long startTime, long endTime,
                            long processingTime, int requestCount, int successCount,
                            int errorCount, Map<String, Object> customMetrics) {
        this.sessionId = sessionId;
        this.startTime = startTime;
        this.endTime = endTime;
        this.processingTime = processingTime;
        this.requestCount = requestCount;
        this.successCount = successCount;
        this.errorCount = errorCount;
        this.customMetrics = customMetrics;
    }
    
    
    public static AIExecutionMetricsBuilder builder() {
        return new AIExecutionMetricsBuilder();
    }
    
    
    public static class AIExecutionMetricsBuilder {
        private String sessionId;
        private long startTime = System.currentTimeMillis();
        private long endTime = System.currentTimeMillis();
        private long processingTime = 0;
        private int requestCount = 1;
        private int successCount = 0;
        private int errorCount = 0;
        private Map<String, Object> customMetrics = new HashMap<>();
        
        public AIExecutionMetricsBuilder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }
        
        public AIExecutionMetricsBuilder startTime(long startTime) {
            this.startTime = startTime;
            return this;
        }
        
        public AIExecutionMetricsBuilder endTime(long endTime) {
            this.endTime = endTime;
            return this;
        }
        
        public AIExecutionMetricsBuilder processingTime(long processingTime) {
            this.processingTime = processingTime;
            return this;
        }
        
        public AIExecutionMetricsBuilder requestCount(int requestCount) {
            this.requestCount = requestCount;
            return this;
        }
        
        public AIExecutionMetricsBuilder successCount(int successCount) {
            this.successCount = successCount;
            return this;
        }
        
        public AIExecutionMetricsBuilder errorCount(int errorCount) {
            this.errorCount = errorCount;
            return this;
        }
        
        public AIExecutionMetricsBuilder customMetrics(Map<String, Object> customMetrics) {
            this.customMetrics = customMetrics != null ? customMetrics : new HashMap<>();
            return this;
        }
        
        public AIExecutionMetricsBuilder success(boolean success) {
            if (success) {
                this.successCount = 1;
                this.errorCount = 0;
            } else {
                this.successCount = 0;
                this.errorCount = 1;
            }
            return this;
        }
        
        public AIExecutionMetrics build() {
            if (sessionId == null) {
                throw new IllegalStateException("sessionId is required");
            }
            return new AIExecutionMetrics(sessionId, startTime, endTime, processingTime,
                                        requestCount, successCount, errorCount, customMetrics);
        }
    }
    
    
    public String getSessionId() { return sessionId; }
    public long getStartTime() { return startTime; }
    public long getEndTime() { return endTime; }
    public long getProcessingTime() { return processingTime; }
    public int getRequestCount() { return requestCount; }
    public int getSuccessCount() { return successCount; }
    public int getErrorCount() { return errorCount; }
    public Map<String, Object> getCustomMetrics() { return customMetrics; }
    
    public double getSuccessRate() {
        return requestCount > 0 ? (double) successCount / requestCount : 0.0;
    }
    
    public double getErrorRate() {
        return requestCount > 0 ? (double) errorCount / requestCount : 0.0;
    }
} 