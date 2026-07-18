package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import org.springframework.ai.document.Document;

import java.util.List;

/** Typed, transport-neutral input required to capture one prompt execution. */
public interface VerificationCaptureContext {

    DomainContext domainContext();

    SecurityEvent securityEvent();

    SecurityDecisionStandardPromptTemplate.SessionContext session();

    SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behavior();

    List<Document> relatedDocuments();

    PromptGenerationResult promptExecution();
}