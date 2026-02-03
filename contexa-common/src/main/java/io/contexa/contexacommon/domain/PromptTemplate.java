package io.contexa.contexacommon.domain;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

public interface PromptTemplate {
    String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata);
    String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo);
    default Class<?> getAIGenerationType() {
        return null;
    }
    TemplateType getSupportedType();
}
