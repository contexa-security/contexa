package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.std.components.prompt.AbstractStandardPromptTemplate;

public class SecurityDecisionStandardPromptTemplate extends AbstractStandardPromptTemplate<SecurityDecisionResponse> {

    private static final String STRUCTURED_PROMPT_CACHE_KEY = "securityDecisionStructuredPrompt";

    private final SecurityPromptTemplate securityPromptTemplate;

    public SecurityDecisionStandardPromptTemplate(SecurityPromptTemplate securityPromptTemplate) {
        super(SecurityDecisionResponse.class);
        this.securityPromptTemplate = securityPromptTemplate;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStructuredPrompt(request).systemText();
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildStructuredPrompt(request).systemText();
    }

    @Override
    public TemplateType getSupportedType() {
        return SecurityDecisionRequest.TEMPLATE_TYPE;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildStructuredPrompt(request).userText();
    }

    private SecurityPromptTemplate.StructuredPrompt buildStructuredPrompt(AIRequest<? extends DomainContext> request) {
        SecurityPromptTemplate.StructuredPrompt cached =
                request.getParameter(STRUCTURED_PROMPT_CACHE_KEY, SecurityPromptTemplate.StructuredPrompt.class);
        if (cached != null) {
            return cached;
        }

        if (!(request instanceof SecurityDecisionRequest securityDecisionRequest)) {
            throw new IllegalArgumentException("SecurityDecisionStandardPromptTemplate supports only SecurityDecisionRequest");
        }

        SecurityDecisionContext context = securityDecisionRequest.getContext();
        SecurityPromptTemplate.StructuredPrompt structuredPrompt = securityPromptTemplate.buildStructuredPrompt(
                context.getSecurityEvent(),
                context.getSessionContext(),
                context.getBehaviorAnalysis(),
                context.getRelatedDocuments()
        );
        request.withParameter(STRUCTURED_PROMPT_CACHE_KEY, structuredPrompt);
        return structuredPrompt;
    }
}
