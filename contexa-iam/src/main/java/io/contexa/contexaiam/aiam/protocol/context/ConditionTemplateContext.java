package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * 조건 템플릿 생성을 위한 전용 컨텍스트
 * 
 * IAMContext 상속으로 타입 안전성 보장
 * 조건 템플릿 특화 메타데이터 제공
 */
@Getter
public class ConditionTemplateContext extends IAMContext {
    
    private final String templateType; // "universal" 또는 "specific"
    private final String resourceIdentifier; // 특화 조건용 리소스 식별자
    private final String methodInfo; // 특화 조건용 메서드 정보
    private final Map<String, Object> templateMetadata; // 추가 메타데이터
    
    public ConditionTemplateContext(SecurityLevel securityLevel, AuditRequirement auditRequirement,
                                   String templateType, String resourceIdentifier, String methodInfo) {
        super(securityLevel, auditRequirement);
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.templateMetadata = new HashMap<>();
    }
    
    public ConditionTemplateContext(String userId, String sessionId, SecurityLevel securityLevel, 
                                   AuditRequirement auditRequirement, String templateType, 
                                   String resourceIdentifier, String methodInfo) {
        super(userId, sessionId, securityLevel, auditRequirement);
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.templateMetadata = new HashMap<>();
    }
    
    /**
     * 범용 조건 템플릿용 컨텍스트 생성
     */
    public static ConditionTemplateContext forUniversalTemplate() {
        return new ConditionTemplateContext(SecurityLevel.STANDARD, AuditRequirement.BASIC,
                "universal", null, null);
    }
    
    /**
     * 특화 조건 템플릿용 컨텍스트 생성
     */
    public static ConditionTemplateContext forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateContext(SecurityLevel.STANDARD, AuditRequirement.BASIC,
                "specific", resourceIdentifier, methodInfo);
    }
    
    @Override
    public String getIAMContextType() {
        return "CONDITION_TEMPLATE";
    }
    
    /**
     * 추가 메타데이터 설정
     */
    public void putTemplateMetadata(String key, Object value) {
        this.templateMetadata.put(key, value);
    }
    
    /**
     * 모든 컨텍스트 데이터 반환
     */
    public Map<String, Object> getContextData() {
        Map<String, Object> data = new HashMap<>();
        data.put("templateType", templateType);
        if (resourceIdentifier != null) {
            data.put("resourceIdentifier", resourceIdentifier);
        }
        if (methodInfo != null) {
            data.put("methodInfo", methodInfo);
        }
        data.putAll(templateMetadata);
        data.putAll(getAllMetadata());
        data.putAll(getAllIAMMetadata());
        return data;
    }
} 