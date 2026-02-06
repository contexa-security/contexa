package io.contexa.contexacommon.domain.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.deserializer.NullSafeLocalDateTimeDeserializer;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Getter
public abstract class AIResponse {

    private final LocalDateTime timestamp;
    private final Map<String, Object> metadata;

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = NullSafeLocalDateTimeDeserializer.class)
    private LocalDateTime executionTime;

    @JsonSetter(nulls = Nulls.SKIP)
    private String errorMessage;

    protected AIResponse() {
        this.timestamp = LocalDateTime.now();
        this.metadata = new ConcurrentHashMap<>();
    }

    public AIResponse withMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }

    public AIResponse withExecutionTime(LocalDateTime executionTime) {
        this.executionTime = executionTime;
        return this;
    }

    public AIResponse withError(String errorMessage) {
        this.errorMessage = errorMessage;
        return this;
    }

    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
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
}