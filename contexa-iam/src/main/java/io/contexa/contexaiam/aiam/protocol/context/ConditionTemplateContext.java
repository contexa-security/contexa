package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
public class ConditionTemplateContext extends DomainContext {

    private final String templateType;
    private final String resourceIdentifier;
    private final String methodInfo;
    private final Map<String, Object> templateMetadata;

    public ConditionTemplateContext(String templateType, String resourceIdentifier, String methodInfo) {
        super();
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.templateMetadata = new HashMap<>();
    }

    public ConditionTemplateContext(String userId, String sessionId,
                                   String templateType, String resourceIdentifier, String methodInfo) {
        super(userId, sessionId);
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.templateMetadata = new HashMap<>();
    }

    public static ConditionTemplateContext forUniversalTemplate() {
        return new ConditionTemplateContext("universal", null, null);
    }

    public static ConditionTemplateContext forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateContext("specific", resourceIdentifier, methodInfo);
    }

    @Override
    public String getDomainType() {
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
        return data;
    }
}
