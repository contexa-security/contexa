package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
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
    private final String baselineContext;
    private final BaselineStatus baselineStatus;
    private final SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns;

    public SecurityPromptBuildContext(SecurityEvent event,
                                      SecurityDecisionStandardPromptTemplate.SessionContext sessionContext,
                                      SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      List<Document> relatedDocuments,
                                      CanonicalSecurityContext canonicalSecurityContext,
                                      String userId,
                                      String baselineContext,
                                      BaselineStatus baselineStatus,
                                      SecurityDecisionStandardPromptTemplate.DetectedPatterns detectedPatterns) {
        this.event = event;
        this.sessionContext = sessionContext;
        this.behaviorAnalysis = behaviorAnalysis;
        this.relatedDocuments = relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of();
        this.canonicalSecurityContext = canonicalSecurityContext;
        this.userId = userId;
        this.baselineContext = baselineContext;
        this.baselineStatus = baselineStatus;
        this.detectedPatterns = detectedPatterns;
    }
}
