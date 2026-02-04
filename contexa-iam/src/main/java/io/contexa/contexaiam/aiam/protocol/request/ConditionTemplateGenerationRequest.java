package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import lombok.Getter;

import java.util.Map;

@Getter
public class ConditionTemplateGenerationRequest extends AIRequest<ConditionTemplateContext> {
    
    private final String template;
    private final String resourceIdentifier; 
    private final String methodInfo; 
    private final Map<String, Object> additionalParameters;
    private final boolean isUniversal;

    public ConditionTemplateGenerationRequest(boolean isUniversal) {
        this(isUniversal, null, null, null, null);
    }

    public ConditionTemplateGenerationRequest(boolean isUniversal, String template, String resourceIdentifier, String methodInfo) {
        this(isUniversal, template, resourceIdentifier, methodInfo, null);
    }
    public ConditionTemplateGenerationRequest(boolean isUniversal, String template, String resourceIdentifier,
                                              String methodInfo, Map<String, Object> additionalParameters) {
        super(createContext(template, resourceIdentifier, methodInfo), new TemplateType("ConditionTemplate"), new DiagnosisType("ConditionTemplate"));
        
        this.template = template;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.additionalParameters = additionalParameters != null ? additionalParameters : Map.of();
        this.isUniversal = isUniversal;

        this.withParameter("templateType", template);
        if (resourceIdentifier != null) {
            this.withParameter("resourceIdentifier", resourceIdentifier);
        }
        if (methodInfo != null) {
            this.withParameter("methodInfo", methodInfo);
        }

        if (additionalParameters != null) {
            additionalParameters.forEach(this.getContext()::putTemplateMetadata);
        }
    }

    public static ConditionTemplateGenerationRequest forUniversalTemplate() {
        return new ConditionTemplateGenerationRequest(true);
    }

    public static ConditionTemplateGenerationRequest forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateGenerationRequest(true, "specific", resourceIdentifier, methodInfo);
    }

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
                template, resourceIdentifier, getRequestId());
    }
} 