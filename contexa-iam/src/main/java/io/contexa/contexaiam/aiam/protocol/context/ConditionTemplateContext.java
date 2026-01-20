package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;


@Getter
public class ConditionTemplateContext extends IAMContext {
    
    private final String templateType; 
    private final String resourceIdentifier; 
    private final String methodInfo; 
    private final Map<String, Object> templateMetadata; 
    
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
    
    
    public static ConditionTemplateContext forUniversalTemplate() {
        return new ConditionTemplateContext(SecurityLevel.STANDARD, AuditRequirement.BASIC,
                "universal", null, null);
    }
    
    
    public static ConditionTemplateContext forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateContext(SecurityLevel.STANDARD, AuditRequirement.BASIC,
                "specific", resourceIdentifier, methodInfo);
    }
    
    @Override
    public String getIAMContextType() {
        return "CONDITION_TEMPLATE";
    }
    
    
    public void putTemplateMetadata(String key, Object value) {
        this.templateMetadata.put(key, value);
    }
    
    
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