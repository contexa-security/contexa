package io.contexa.contexaiam.aiam.protocol.context;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class ConditionTemplateContext extends DomainContext {

    private final String templateType;
    private final String resourceIdentifier;
    private final String methodInfo;
    private final List<Map<String, String>> resourceBatch;
    private final Map<String, Object> templateMetadata;

    public ConditionTemplateContext(String templateType, String resourceIdentifier, String methodInfo) {
        this(templateType, resourceIdentifier, methodInfo, null);
    }

    private ConditionTemplateContext(String templateType, String resourceIdentifier,
                                     String methodInfo, List<Map<String, String>> resourceBatch) {
        super();
        this.templateType = templateType;
        this.resourceIdentifier = resourceIdentifier;
        this.methodInfo = methodInfo;
        this.resourceBatch = resourceBatch;
        this.templateMetadata = new HashMap<>();
    }

    public static ConditionTemplateContext forUniversalTemplate() {
        return new ConditionTemplateContext("universal", null, null);
    }

    public static ConditionTemplateContext forSpecificTemplate(String resourceIdentifier, String methodInfo) {
        return new ConditionTemplateContext("specific", resourceIdentifier, methodInfo);
    }

    public static ConditionTemplateContext forSpecificBatch(List<Map<String, String>> resourceBatch) {
        return new ConditionTemplateContext("specific", null, null, resourceBatch);
    }

    @Override
    public String getDomainType() {
        return "CONDITION_TEMPLATE";
    }

    public void putTemplateMetadata(String key, Object value) {
        this.templateMetadata.put(key, value);
    }

}
