package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import lombok.Getter;
import org.springframework.ai.document.Document;

import java.util.List;

@Getter
public class SecurityDecisionContext extends DomainContext {

    private final SecurityEvent securityEvent;
    private final SecurityPromptTemplate.SessionContext sessionContext;
    private final SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis;
    private final List<Document> relatedDocuments;

    public SecurityDecisionContext(SecurityEvent securityEvent,
                                   SecurityPromptTemplate.SessionContext sessionContext,
                                   SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis,
                                   List<Document> relatedDocuments) {
        super(
                securityEvent != null ? securityEvent.getUserId() : null,
                securityEvent != null ? securityEvent.getSessionId() : null
        );
        this.securityEvent = securityEvent;
        this.sessionContext = sessionContext;
        this.behaviorAnalysis = behaviorAnalysis;
        this.relatedDocuments = relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of();
        if (securityEvent != null && securityEvent.getMetadata() != null) {
            Object organizationId = securityEvent.getMetadata().get("organizationId");
            if (organizationId instanceof String organization) {
                setOrganizationId(organization);
            }
        }
    }

    @Override
    public String getDomainType() {
        return "POST_AUTH_SECURITY_DECISION";
    }
}
