package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import lombok.Getter;
import org.springframework.ai.document.Document;

import java.util.List;

@Getter
public class SecurityPromptBuildContext {

    private final SecurityEvent event;
    private final SecurityDecisionStandardPromptTemplate.SessionContext sessionContext;
    private final SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis;
    private final List<Document> relatedDocuments;
    private final CanonicalSecurityContext canonicalSecurityContext;
    private final String userId;
    private final BaselineStatus baselineStatus;
    private final SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns;
    private final LearningContextEvidence learningContextEvidence;
    private final StructuredOutputMode structuredOutputMode;

    public SecurityPromptBuildContext(SecurityEvent event,
                                      SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
                                      SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      List<Document> relatedDocuments,
                                      CanonicalSecurityContext canonicalSecurityContext,
                                      String userId,
                                      BaselineStatus baselineStatus,
                                      SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns,
                                      LearningContextEvidence learningContextEvidence,
                                      StructuredOutputMode structuredOutputMode) {
        this.event = event;
        this.sessionContext = sessionContext;
        this.behaviorAnalysis = behaviorAnalysis;
        this.relatedDocuments = relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of();
        this.canonicalSecurityContext = canonicalSecurityContext;
        this.userId = userId;
        this.baselineStatus = baselineStatus;
        this.detectedPatterns = detectedPatterns;
        this.learningContextEvidence = learningContextEvidence;
        this.structuredOutputMode = structuredOutputMode;
    }
}
