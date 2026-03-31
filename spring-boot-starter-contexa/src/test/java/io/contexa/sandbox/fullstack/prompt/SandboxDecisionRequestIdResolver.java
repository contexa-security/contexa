package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.springframework.util.StringUtils;

import java.util.Map;

final class SandboxDecisionRequestIdResolver {

    private SandboxDecisionRequestIdResolver() {
    }

    static String resolve(
            AIRequest<? extends DomainContext> request,
            PipelineExecutionContext context,
            PromptGenerationResult promptGenerationResult) {
        String requestIdFromPromptMetadata = requestIdFromPromptMetadata(promptGenerationResult);
        if (StringUtils.hasText(requestIdFromPromptMetadata)) {
            return requestIdFromPromptMetadata;
        }

        String requestIdFromSecurityContext = requestIdFromSecurityContext(request);
        if (StringUtils.hasText(requestIdFromSecurityContext)) {
            return requestIdFromSecurityContext;
        }

        if (request != null && StringUtils.hasText(request.getRequestId())) {
            return request.getRequestId();
        }

        return context != null ? context.getExecutionId() : null;
    }

    private static String requestIdFromPromptMetadata(PromptGenerationResult promptGenerationResult) {
        if (promptGenerationResult == null || promptGenerationResult.getMetadata() == null) {
            return null;
        }
        return requestIdFromMap(promptGenerationResult.getMetadata());
    }

    private static String requestIdFromSecurityContext(AIRequest<? extends DomainContext> request) {
        if (request == null || !(request.getContext() instanceof SecurityDecisionContext securityDecisionContext)) {
            return null;
        }
        return requestIdFromEvent(securityDecisionContext.getSecurityEvent());
    }

    private static String requestIdFromEvent(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        return requestIdFromMap(event.getMetadata());
    }

    private static String requestIdFromMap(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        Object requestId = metadata.get("requestId");
        if (requestId instanceof String text && StringUtils.hasText(text)) {
            return text.trim();
        }
        Object correlationId = metadata.get("correlationId");
        if (correlationId instanceof String text && StringUtils.hasText(text)) {
            return text.trim();
        }
        return null;
    }
}
