package io.contexa.contexacommon.domain.context;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;


@Getter
@Setter
public abstract class DomainContext {
    
    private final String contextId;
    private final LocalDateTime createdAt;
    private final Map<String, Object> metadata;
    private String userId;
    private String sessionId;
    private String organizationId;

    protected DomainContext() {
        this.contextId = UUID.randomUUID().toString();
        this.createdAt = LocalDateTime.now();
        this.metadata = new ConcurrentHashMap<>();
    }
    
    protected DomainContext(String userId, String sessionId) {
        this();
        this.userId = userId;
        this.sessionId = sessionId;
    }
    

    public abstract String getDomainType();

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }

    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    public Map<String, Object> getAllMetadata() {
        return Map.copyOf(metadata);
    }

    @Override
    public String toString() {
        return String.format("%s{id='%s', domain='%s'}",
                getClass().getSimpleName(), contextId, getDomainType());
    }
} 