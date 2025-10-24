package io.contexa.contexacore.infra.session;

/**
 * AI 실행 결과
 */
public class AIExecutionResult {
    private final String sessionId;
    private final boolean success;
    private final Object result;
    private final String errorMessage;
    private final long completionTime;
    private final AIExecutionMetrics metrics;
    
    public AIExecutionResult(String sessionId, boolean success, Object result,
                           String errorMessage, long completionTime, 
                           AIExecutionMetrics metrics) {
        this.sessionId = sessionId;
        this.success = success;
        this.result = result;
        this.errorMessage = errorMessage;
        this.completionTime = completionTime;
        this.metrics = metrics;
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public boolean isSuccess() { return success; }
    public Object getResult() { return result; }
    public String getErrorMessage() { return errorMessage; }
    public long getCompletionTime() { return completionTime; }
    public AIExecutionMetrics getMetrics() { return metrics; }
    
    public static AIExecutionResult success(String sessionId, Object result, 
                                          long completionTime, AIExecutionMetrics metrics) {
        return new AIExecutionResult(sessionId, true, result, null, completionTime, metrics);
    }
    
    public static AIExecutionResult failure(String sessionId, String errorMessage, 
                                          long completionTime, AIExecutionMetrics metrics) {
        return new AIExecutionResult(sessionId, false, null, errorMessage, completionTime, metrics);
    }
} 