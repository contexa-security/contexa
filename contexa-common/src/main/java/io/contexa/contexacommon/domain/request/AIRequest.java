package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Getter
public class AIRequest<T extends DomainContext> {

    private final String requestId;
    private final LocalDateTime timestamp;
    private final T context;
    private final String promptTemplate;
    private final Map<String, Object> parameters;
    private final RequestPriority priority;
    private final RequestType requestType;
    private DiagnosisType diagnosisType;
    private String organizationId;
    private String tenantId;

    private List<Object> toolProviders = new ArrayList<>();

    private boolean isStreamingRequired = false;
    private int timeoutSeconds = 300;

    public AIRequest(T context, String promptTemplate, String organizationId) {
        this.requestId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.context = context;
        this.promptTemplate = promptTemplate;
        this.parameters = new ConcurrentHashMap<>();
        this.priority = RequestPriority.NORMAL;
        this.requestType = RequestType.STANDARD;
        this.organizationId = organizationId;
    }

    public AIRequest(T context, String promptTemplate, RequestPriority priority, RequestType requestType) {
        this.requestId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.context = context;
        this.promptTemplate = promptTemplate;
        this.parameters = new ConcurrentHashMap<>();
        this.priority = priority;
        this.requestType = requestType;
    }

    
    public AIRequest<T> withParameter(String key, Object value) {
        this.parameters.put(key, value);
        return this;
    }

    
    public AIRequest<T> withStreaming(boolean required) {
        this.isStreamingRequired = required;
        return this;
    }

    
    public AIRequest<T> withDiagnosisType(DiagnosisType diagnosisType) {
        this.diagnosisType = diagnosisType;
        return this;
    }

    
    public AIRequest<T> withTimeout(int seconds) {
        this.timeoutSeconds = seconds;
        return this;
    }

    
    public <P> P getParameter(String key, Class<P> type) {
        Object value = parameters.get(key);
        return type.isInstance(value) ? (P) value : null;
    }

    public Map<String, Object> getParameters() { return Map.copyOf(parameters); }
    
    
    public T getContext() { return context; }
    public String getPromptTemplate() { return promptTemplate; }
    public String getRequestId() { return requestId; }

    
    public AIRequest<T> withOrganizationId(String organizationId) {
        this.organizationId = organizationId;
        return this;
    }

    
    public AIRequest<T> withTenantId(String tenantId) {
        this.tenantId = tenantId;
        return this;
    }

    
    public AIRequest<T> withToolProvider(Object toolProvider) {
        this.toolProviders.add(toolProvider);
        return this;
    }

    
    public AIRequest<T> withToolProviders(List<Object> toolProviders) {
        this.toolProviders.addAll(toolProviders);
        return this;
    }

    
    public List<Object> getToolProviders() {
        return Collections.unmodifiableList(toolProviders);
    }

    
    public boolean hasToolProviders() {
        return !toolProviders.isEmpty();
    }

    
    public enum RequestPriority {
        LOW(1), NORMAL(5), HIGH(8), CRITICAL(10);

        private final int level;

        RequestPriority(int level) {
            this.level = level;
        }

        public int getLevel() { return level; }
    }

    
    public enum RequestType {
        STANDARD,           
        STREAMING,          
        BATCH,              
        ANALYSIS,           
        GENERATION,         
        VALIDATION          
    }

    @Override
    public String toString() {
        return String.format("AIRequest{id='%s', operation='%s', domain='%s', priority=%s}",
                requestId, promptTemplate, context.getDomainType(), priority);
    }
} 