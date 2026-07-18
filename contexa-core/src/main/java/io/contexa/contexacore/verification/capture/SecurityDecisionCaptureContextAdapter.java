package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.springframework.ai.document.Document;

import java.util.List;
import java.util.Objects;

/** Explicit adapter from the security decision domain object to the capture SPI. */
public final class SecurityDecisionCaptureContextAdapter implements VerificationCaptureContext {

    private final SecurityDecisionContext context;
    private final PromptGenerationResult promptExecution;

    public SecurityDecisionCaptureContextAdapter(
            SecurityDecisionContext context,
            PromptGenerationResult promptExecution
    ) {
        this.context = Objects.requireNonNull(context, "context must not be null");
        this.promptExecution = Objects.requireNonNull(promptExecution, "promptExecution must not be null");
    }

    @Override
    public DomainContext domainContext() {
        return context;
    }

    @Override
    public SecurityEvent securityEvent() {
        return context.getSecurityEvent();
    }

    @Override
    public SecurityDecisionStandardPromptTemplate.SessionContext session() {
        return context.getSessionContext();
    }

    @Override
    public SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behavior() {
        return context.getBehaviorAnalysis();
    }

    @Override
    public List<Document> relatedDocuments() {
        return context.getRelatedDocuments() == null ? List.of() : List.copyOf(context.getRelatedDocuments());
    }

    @Override
    public PromptGenerationResult promptExecution() {
        return promptExecution;
    }
}