package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.Getter;
import org.springframework.ai.document.Document;

import java.util.List;

@Getter
public class SecurityPromptBuildContext {

    private final SecurityEvent event;
    private final SecurityPromptTemplate.SessionContext sessionContext;
    private final SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis;
    private final List<Document> relatedDocuments;
    private final CanonicalSecurityContext canonicalSecurityContext;
    private final String userId;
    private final String baselineContext;
    private final BaselineStatus baselineStatus;
    private final SecurityPromptTemplate.DetectedPatterns detectedPatterns;

    public SecurityPromptBuildContext(SecurityEvent event,
                                      SecurityPromptTemplate.SessionContext sessionContext,
                                      SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                      List<Document> relatedDocuments,
                                      CanonicalSecurityContext canonicalSecurityContext,
                                      String userId,
                                      String baselineContext,
                                      BaselineStatus baselineStatus,
                                      SecurityPromptTemplate.DetectedPatterns detectedPatterns) {
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
