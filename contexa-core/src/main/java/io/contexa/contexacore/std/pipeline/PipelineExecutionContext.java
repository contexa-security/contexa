package io.contexa.contexacore.std.pipeline;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashMap;

public class PipelineExecutionContext {
    
    private final String executionId;
    private final Map<String, Object> parameters;
    private final Map<String, Object> stepResults;
    private final Map<String, Object> sharedData;
    private final Map<String, Object> metadata;
    private final long startTime;

    public PipelineExecutionContext() {
        this.executionId = "unknown";
        this.parameters = new ConcurrentHashMap<>();
        this.stepResults = new ConcurrentHashMap<>();
        this.sharedData = new ConcurrentHashMap<>();
        this.metadata = new ConcurrentHashMap<>();
        this.startTime = System.currentTimeMillis();
    }

    public PipelineExecutionContext(String executionId, Map<String, Object> parameters) {
        this.executionId = executionId;
        this.parameters = parameters != null ? parameters : new HashMap<>();
        this.stepResults = new ConcurrentHashMap<>();
        this.sharedData = new ConcurrentHashMap<>();
        this.metadata = new ConcurrentHashMap<>();
        this.startTime = System.currentTimeMillis();
    }

    public PipelineExecutionContext(String executionId) {
        this(executionId, new HashMap<>());
    }
    public void addStepResult(PipelineConfiguration.PipelineStep step, Object result) {
        if (step == null) {
            throw new IllegalArgumentException("Pipeline step cannot be null");
        }
        String stepName = step.name();
        Object safeResult = result != null ? result : "NULL_RESULT";
        stepResults.put(stepName, safeResult);
    }

    public <T> T getStepResult(String stepName, Class<T> type) {
        Object result = stepResults.get(stepName);
        if ("NULL_RESULT".equals(result)) {
            return null;
        }
        return type.isInstance(result) ? (T) result : null;
    }

    public <T> T getStepResult(PipelineConfiguration.PipelineStep step, Class<T> type) {
        return getStepResult(step.name(), type);
    }
    
    public Object get(String key) {
        Object result = sharedData.get(key);
        if (result == null) {
            result = stepResults.get(key);
        }
        return result;
    }
    
    public <T> T get(String key, Class<T> type) {
        Object result = get(key);
        return type.isInstance(result) ? type.cast(result) : null;
    }

    public <T> T getParameter(String key, Class<T> type) {
        Object value = parameters.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    public long getExecutionTime() {
        return System.currentTimeMillis() - startTime;
    }

    public String getExecutionId() {
        return executionId;
    }

    public void addMetadata(String key, Object value) {
        if (key == null) {
            throw new IllegalArgumentException("Metadata key cannot be null");
        }
        Object safeValue = value != null ? value : "NULL_VALUE";
        metadata.put(key, safeValue);
    }
    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        if ("NULL_VALUE".equals(value)) {
            return null;
        }
        return type.isInstance(value) ? type.cast(value) : null;
    }
}