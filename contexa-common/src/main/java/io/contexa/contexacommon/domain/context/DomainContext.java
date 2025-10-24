package io.contexa.contexacommon.domain.context;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 모든 도메인 컨텍스트의 기본 추상 클래스
 * AI Core 시스템에서 다양한 도메인의 컨텍스트 정보를 통합 관리
 */
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
    
    /**
     * 도메인 타입을 반환합니다
     * @return 도메인 타입 (예: "IAM", "SHOP", "BATCH")
     */
    public abstract String getDomainType();
    
    /**
     * 컨텍스트의 우선순위 레벨을 반환합니다
     * @return 우선순위 (1-10, 높을수록 중요)
     */
    public abstract int getPriorityLevel();
    
    /**
     * 메타데이터를 추가합니다
     * @param key 키
     * @param value 값
     */
    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }
    
    /**
     * 메타데이터를 조회합니다
     * @param key 키
     * @param type 값의 타입
     * @return 값 (존재하지 않으면 null)
     */
    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }
    public Map<String, Object> getAllMetadata() { return Map.copyOf(metadata); }
    
    @Override
    public String toString() {
        return String.format("%s{id='%s', domain='%s', priority=%d}", 
                getClass().getSimpleName(), contextId, getDomainType(), getPriorityLevel());
    }
} 