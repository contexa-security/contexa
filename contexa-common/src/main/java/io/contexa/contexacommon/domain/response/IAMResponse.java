package io.contexa.contexacommon.domain.response;

import io.contexa.contexacommon.domain.AuditInfo;
import io.contexa.contexacommon.domain.ComplianceInfo;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IAM AI 응답 클래스
 * AI Core 응답을 확장하여 IAM 특화 정보를 제공
 */
@Getter
@Setter
public abstract class IAMResponse extends AIResponse {
    
    private final AuditInfo auditInfo;
    private final Map<String, Object> iamSpecificMetadata;
    
    private String organizationId;
    private String tenantId;
    private boolean sensitiveDataIncluded;
    private ComplianceInfo complianceInfo;
    
    protected IAMResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
        this.auditInfo = new AuditInfo();
        this.iamSpecificMetadata = new ConcurrentHashMap<>();
        this.sensitiveDataIncluded = false;
    }
    
    @Override
    public abstract String getResponseType();
    
    public void withIAMMetadata(String key, Object value) {
        this.iamSpecificMetadata.put(key, value);
    }

    public <T> T getIAMMetadata(String key, Class<T> type) {
        Object value = iamSpecificMetadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }
    
    public Map<String, Object> getAllIAMMetadata() { return Map.copyOf(iamSpecificMetadata); }
}
