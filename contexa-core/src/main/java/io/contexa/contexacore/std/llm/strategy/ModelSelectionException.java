package io.contexa.contexacore.std.llm.strategy;

public class ModelSelectionException extends RuntimeException {
    
    private final String requestedModel;
    private final String failureReason;
    
    public ModelSelectionException(String message) {
        super(message);
        this.requestedModel = null;
        this.failureReason = message;
    }
    
    public ModelSelectionException(String message, Throwable cause) {
        super(message, cause);
        this.requestedModel = null;
        this.failureReason = message;
    }
    
    public ModelSelectionException(String requestedModel, String failureReason, Throwable cause) {
        super(String.format("모델 선택 실패 - 요청 모델: %s, 실패 사유: %s", requestedModel, failureReason), cause);
        this.requestedModel = requestedModel;
        this.failureReason = failureReason;
    }
    
    public String getRequestedModel() {
        return requestedModel;
    }
    
    public String getFailureReason() {
        return failureReason;
    }
}