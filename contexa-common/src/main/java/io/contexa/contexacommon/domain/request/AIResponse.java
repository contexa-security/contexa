package io.contexa.contexacommon.domain.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.deserializer.NullSafeLocalDateTimeDeserializer;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Getter
public abstract class AIResponse {

    private final String responseId;
    private final LocalDateTime timestamp;
    private final String requestId;
    private final ExecutionStatus status;
    private final Map<String, Object> metadata;

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = NullSafeLocalDateTimeDeserializer.class)
    private LocalDateTime executionTime;

    @JsonSetter(nulls = Nulls.SKIP)
    private String errorMessage;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private List<String> warnings;

    private double confidenceScore = 0.0;

    @JsonSetter(nulls = Nulls.SKIP)
    private String aiModel;

    protected AIResponse(String requestId, ExecutionStatus status) {
        this.responseId = java.util.UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.requestId = requestId;
        this.status = status;
        this.metadata = new ConcurrentHashMap<>();
    }

    
    public abstract Object getData();

    
    public abstract String getResponseType();

    
    public AIResponse withMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }

    
    public AIResponse withExecutionTime(LocalDateTime executionTime) {
        this.executionTime = executionTime;
        return this;
    }

    
    public AIResponse withConfidenceScore(double confidenceScore) {
        this.confidenceScore = Math.max(0.0, Math.min(1.0, confidenceScore));
        return this;
    }

    
    public AIResponse withAiModel(String aiModel) {
        this.aiModel = aiModel;
        return this;
    }

    
    public AIResponse withWarnings(List<String> warnings) {
        this.warnings = warnings;
        return this;
    }

    
    public AIResponse withError(String errorMessage) {
        this.errorMessage = errorMessage;
        return this;
    }

    
    @SuppressWarnings("unchecked")
    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    
    public boolean isSuccess() {
        return status == ExecutionStatus.SUCCESS;
    }

    
    public boolean isFailure() {
        return status == ExecutionStatus.FAILURE;
    }

    
    public boolean hasWarnings() {
        return warnings != null && !warnings.isEmpty();
    }

    public Map<String, Object> getAllMetadata() { return Map.copyOf(metadata); }

    
    public enum ExecutionStatus {
        SUCCESS,            
        FAILURE,            
        PARTIAL_SUCCESS,    
        COMPLETED,          
        TIMEOUT,            
        CANCELLED,          
        INVESTIGATING,      
        IN_PROGRESS         
    }

    @Override
    public String toString() {
        return String.format("AIResponse{id='%s', type='%s', status=%s, confidence=%.2f}",
                responseId, getResponseType(), status, confidenceScore);
    }
}