package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.domain.request.IAMRequest;
import lombok.Getter;

import java.util.Map;


/**
 * 조건 템플릿 생성 요청 DTO
 * 
 * 타입 안전성: 구체적인 요청 타입
 * 범용/특화 조건 템플릿 생성 지원
 */
@Getter
public class ConditionTemplateGenerationRequest extends IAMRequest<ConditionTemplateContext> {
    
    private final String templateType; // "universal" 또는 "specific"
    private final String resourceIdentifier; // 특화 조건용 (선택적)
    private final String methodInfo; // 특화 조건용 (선택적)
    private final Map<String, Object> additionalParameters;
    private final boolean isUniversal;

    public ConditionTemplateGenerationRequest(boolean isUniversal) {
        this(isUniversal, null, null, null, null);
    }

    public ConditionTemplateGenerationRequest(boolean isUniversal, String templateType, String resourceIdentifier, String methodInfo) {
        this(isUniversal, templateType, resourceIdentifier, methodInfo, null);
    }
    public ConditionTemplateGenerationRequest(boolean isUniversal, String templateType, String resourceIdentifier,
                                               String methodInfo, Map<String, Object> additionalParameters) {
        super(createContext(templateType, resourceIdentifier, methodInfo), "conditionTemplateGeneration");
        
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.additionalParameters = additionalParameters != null ? additionalParameters : Map.of();
        this.isUniversal = isUniversal;
        this.withDiagnosisType(DiagnosisType.CONDITION_TEMPLATE);
        
        this.withParameter("templateType", templateType);
        if (resourceIdentifier != null) {
            this.withParameter("resourceIdentifier", resourceIdentifier);
        }
        if (methodInfo != null) {
            this.withParameter("methodInfo", methodInfo);
        }
        
        // 컨텍스트에 추가 파라미터 설정
        if (additionalParameters != null) {
            additionalParameters.forEach(this.getContext()::putTemplateMetadata);
        }
    }
    
    /**
     * 범용 조건 템플릿 생성 요청
     */
    public static ConditionTemplateGenerationRequest forUniversalTemplate() {
        return new ConditionTemplateGenerationRequest(true);
    }
    
    /**
     * 특화 조건 템플릿 생성 요청
     */
    public static ConditionTemplateGenerationRequest forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateGenerationRequest(true, "specific", resourceIdentifier, methodInfo);
    }
    
    /**
     * 컨텍스트 생성 헬퍼 메서드
     */
    private static ConditionTemplateContext createContext(String templateType, String resourceIdentifier, String methodInfo) {
        if ("universal".equals(templateType)) {
            return ConditionTemplateContext.forUniversalTemplate();
        } else if ("specific".equals(templateType)) {
            return ConditionTemplateContext.forSpecificTemplate(resourceIdentifier, methodInfo);
        } else {
            throw new IllegalArgumentException("지원하지 않는 템플릿 타입: " + templateType);
        }
    }
    
    @Override
    public String toString() {
        return String.format("ConditionTemplateGenerationRequest{type='%s', resource='%s', requestId='%s'}", 
                templateType, resourceIdentifier, getRequestId());
    }
} 